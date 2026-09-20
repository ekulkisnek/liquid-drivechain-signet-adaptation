//! Bounded, opt-in signed-promise observation. This is NOT a payment-admission
//! service: signature validity does not prove confirmed collateral or principal.
mod server;
pub use server::{serve, ServerConfig};

use crate::{
    elements::{
        hashes::{sha256, Hash},
        OutPoint,
    },
    operator::{Bond, Config, Receipt},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

pub const MAX_SESSIONS: usize = 128;
pub const MAX_FRAME: usize = 4096;
const MAX_JOURNAL: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    #[serde(with = "crate::operator::outpoint")]
    pub bond: OutPoint,
    pub config: Config,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub sessions: Vec<Session>,
}
pub struct ValidatedProfile {
    pub id: String,
    pub bonds: BTreeMap<OutPoint, Bond>,
}
impl Profile {
    /// Administrative allowlist. Never compile arbitrary covenant parameters
    /// received from peers, and never accept a peer-supplied profile as trusted.
    pub fn validate(mut self) -> Result<Arc<ValidatedProfile>, String> {
        if self.version != 1 || self.sessions.is_empty() || self.sessions.len() > MAX_SESSIONS {
            return Err("invalid profile version or session count".into());
        }
        self.sessions.sort_by_key(|s| s.bond);
        let first = &self.sessions[0].config;
        let mut bonds = BTreeMap::new();
        let mut protected = std::collections::BTreeSet::new();
        for session in &self.sessions {
            if session.bond.is_null()
                || session.bond == session.config.protected_output
                || session.config.genesis != first.genesis
                || session.config.fee_asset != first.fee_asset
                || bonds.contains_key(&session.bond)
                || !protected.insert(session.config.protected_output)
            {
                return Err(
                    "profile requires unique bonds/subjects on one chain and fee asset".into(),
                );
            }
            bonds.insert(session.bond, session.config.compile()?);
        }
        let encoded = serde_json::to_vec(&self).map_err(|e| e.to_string())?;
        Ok(Arc::new(ValidatedProfile {
            id: sha256::Hash::hash(&encoded).to_string(),
            bonds,
        }))
    }
}
impl ValidatedProfile {
    pub fn verify(&self, receipt: &Receipt) -> Result<(), String> {
        self.bonds
            .get(&receipt.bond)
            .ok_or("unknown bond/session")?
            .verify(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub seq: u64,
    pub receipt: Receipt,
    /// The first conflicting receipt; enough to construct same-bond evidence.
    pub conflict_with: Option<Receipt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub stream: String,
    pub seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    Subscribe {
        profile: String,
        cursor: Option<Cursor>,
    },
    Publish {
        receipt: Receipt,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerMessage {
    Begin {
        profile: String,
        stream: String,
        from: u64,
        through: u64,
    },
    Event {
        event: Box<Event>,
    },
    CaughtUp {
        cursor: Cursor,
    },
    Heartbeat {
        cursor: Cursor,
    },
    Published {
        seq: u64,
        status: String,
    },
    Error {
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    profile: String,
    stream: String,
}

/// Append-only, fsynced evidence with an exclusive file lock. Two distinct
/// promises per allowlisted subject are retained forever; conflict is sticky.
/// No silent eviction/rotation of evidence or sequence numbers is permitted.
pub struct Store {
    pub profile: Arc<ValidatedProfile>,
    pub stream: String,
    pub events: Vec<Event>,
    journal: File,
    failed: bool,
}
impl Store {
    pub fn open(path: &Path, profile: Arc<ValidatedProfile>) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut journal = options.open(path).map_err(|e| e.to_string())?;
        journal
            .try_lock()
            .map_err(|_| "journal is already locked or locking unavailable")?;
        if !journal.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("journal must be a regular file".into());
        }
        let mut bytes = Vec::new();
        (&mut journal)
            .take(MAX_JOURNAL + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_JOURNAL {
            return Err("oversized journal".into());
        }
        let mut records = Vec::new();
        let header: Header = if bytes.is_empty() {
            let mut id = [0; 32];
            getrandom::getrandom(&mut id).map_err(|_| "random stream ID unavailable")?;
            let h = Header {
                version: 1,
                profile: profile.id.clone(),
                stream: hex::encode(id),
            };
            append(&mut journal, &h)?;
            h
        } else {
            if bytes.last() != Some(&b'\n') {
                return Err("torn journal: preserve it and restore from verified evidence".into());
            }
            let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
            let h = serde_json::from_slice(lines.next().ok_or("missing journal header")?)
                .map_err(|_| "bad journal header")?;
            for line in lines {
                if line.is_empty() {
                    return Err("empty journal record".into());
                }
                if line.len() > MAX_FRAME {
                    return Err("oversized journal record".into());
                }
                records
                    .push(serde_json::from_slice::<Event>(line).map_err(|_| "bad journal event")?);
            }
            h
        };
        if header.version != 1
            || header.profile != profile.id
            || header.stream.len() != 64
            || hex::decode(&header.stream).is_err()
        {
            return Err("journal/profile mismatch".into());
        }
        let mut store = Self {
            profile,
            stream: header.stream,
            events: Vec::new(),
            journal,
            failed: false,
        };
        for record in records {
            let (expected, _) = store.prepare(&record.receipt)?;
            if expected.as_ref() != Some(&record) {
                return Err("noncanonical or duplicate journal event".into());
            }
            store.events.push(record);
        }
        Ok(store)
    }
    pub fn head(&self) -> u64 {
        self.events.len() as u64
    }
    pub fn replay(&self, cursor: Option<&Cursor>) -> Result<Vec<Event>, String> {
        if self.failed {
            return Err("journal unavailable".into());
        }
        let from = if let Some(c) = cursor {
            if c.stream != self.stream || c.seq > self.head() {
                return Err("cursor gap or stream changed; full revalidation required".into());
            }
            c.seq as usize
        } else {
            0
        };
        Ok(self.events[from..].to_vec())
    }
    fn prepare(&self, receipt: &Receipt) -> Result<(Option<Event>, (&'static str, u64)), String> {
        if self.failed {
            return Err("journal unavailable".into());
        }
        self.profile.verify(receipt)?;
        let previous: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.receipt.bond == receipt.bond)
            .collect();
        if let Some(duplicate) = previous.iter().find(|e| e.receipt.txid == receipt.txid) {
            return Ok((None, ("duplicate", duplicate.seq)));
        }
        if previous.len() == 2 {
            return Ok((None, ("already_conflicted", previous[1].seq)));
        }
        let event = Event {
            seq: self.head() + 1,
            receipt: receipt.clone(),
            conflict_with: previous.first().map(|e| e.receipt.clone()),
        };
        let seq = event.seq;
        Ok((Some(event), ("stored", seq)))
    }
    pub fn publish(
        &mut self,
        receipt: Receipt,
    ) -> Result<(Option<Event>, (&'static str, u64)), String> {
        let (event, status) = self.prepare(&receipt)?;
        if let Some(ref event) = event {
            if let Err(error) = append(&mut self.journal, event) {
                self.failed = true;
                return Err(error);
            }
            self.events.push(event.clone());
        }
        Ok((event, status))
    }
}
fn append(file: &mut File, value: &impl Serialize) -> Result<(), String> {
    let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if line.len() > MAX_FRAME {
        return Err("oversized journal record".into());
    }
    line.push(b'\n');
    file.write_all(&line)
        .and_then(|_| file.sync_all())
        .map_err(|_| "journal write failed; monitoring disabled".into())
}

/// Per-connection cursor validation shared by the peer client and tests.
/// A fresh process must request a full snapshot, not just restore a bare cursor.
#[derive(Clone, Default)]
pub struct Tracker {
    pub cursor: Option<Cursor>,
    pub caught_up: bool,
    through: Option<u64>,
}
impl Tracker {
    pub fn disconnected(&mut self) {
        self.caught_up = false;
        self.through = None;
    }
    pub fn process(
        &mut self,
        message: &ServerMessage,
        profile: &ValidatedProfile,
    ) -> Result<Option<Receipt>, String> {
        let result = self.process_inner(message, profile);
        if result.is_err() {
            self.disconnected();
        }
        result
    }
    fn process_inner(
        &mut self,
        m: &ServerMessage,
        p: &ValidatedProfile,
    ) -> Result<Option<Receipt>, String> {
        let max_events = (p.bonds.len() * 2) as u64;
        match m {
            ServerMessage::Begin {
                profile,
                stream,
                from,
                through,
            } => {
                if self.through.is_some()
                    || *profile != p.id
                    || *through < *from
                    || *through > max_events
                    || stream.len() != 64
                    || hex::decode(stream).is_err()
                {
                    return Err("invalid synchronization header".into());
                }
                match &self.cursor {
                    Some(c) if c.stream != *stream || c.seq != *from => {
                        return Err("stream/cursor gap".into())
                    }
                    None if *from != 0 => return Err("snapshot must start at zero".into()),
                    _ => (),
                }
                self.cursor = Some(Cursor {
                    stream: stream.clone(),
                    seq: *from,
                });
                self.through = Some(*through);
                self.caught_up = false;
            }
            ServerMessage::Event { event } => {
                let c = self.cursor.as_mut().ok_or("event before begin")?;
                if self.through.is_none()
                    || event.seq != c.seq + 1
                    || event.seq > max_events
                    || (!self.caught_up && Some(event.seq) > self.through)
                {
                    return Err("event sequence gap".into());
                }
                p.verify(&event.receipt)?;
                if let Some(other) = &event.conflict_with {
                    p.verify(other)?;
                    if other.bond != event.receipt.bond || other.txid == event.receipt.txid {
                        return Err("invalid conflict evidence".into());
                    }
                }
                c.seq = event.seq;
                return Ok(Some(event.receipt.clone()));
            }
            ServerMessage::CaughtUp { cursor } => {
                if self.caught_up
                    || self.cursor.as_ref() != Some(cursor)
                    || self.through != Some(cursor.seq)
                {
                    return Err("incomplete replay".into());
                }
                self.caught_up = true;
            }
            ServerMessage::Heartbeat { cursor } => {
                if !self.caught_up || self.cursor.as_ref() != Some(cursor) {
                    return Err("heartbeat gap".into());
                }
            }
            ServerMessage::Published { .. } => (),
            ServerMessage::Error { .. } => return Err("relay reported unavailable/gap".into()),
        }
        Ok(None)
    }
}
