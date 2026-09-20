#![cfg(feature = "relay")]
mod common;
use common::{collateral, operator::*, transfer};
use elementsplus_preconf::{operator::Receipt, relay::*};
use futures_util::{SinkExt, StreamExt};
use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut id = [0; 16];
        getrandom::getrandom(&mut id).unwrap();
        let path = std::env::temp_dir().join(format!("preconf-relay-test-{}", hex::encode(id)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("receipts.jsonl")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn profile() -> Arc<ValidatedProfile> {
    static PROFILE: OnceLock<Arc<ValidatedProfile>> = OnceLock::new();
    PROFILE
        .get_or_init(|| {
            Profile {
                version: 1,
                sessions: vec![Session {
                    bond: collateral(),
                    config: config(),
                }],
            }
            .validate()
            .unwrap()
        })
        .clone()
}
fn store(temp: &Temp) -> Store {
    Store::open(&temp.journal(), profile()).unwrap()
}

#[test]
fn durable_conflicts_deduplication_and_replay_survive_restart() {
    let temp = Temp::new();
    let (a, b) = evidence();
    let stream;
    {
        let mut s = store(&temp);
        stream = s.stream.clone();
        assert!(
            Store::open(&temp.journal(), profile()).is_err(),
            "exclusive journal lock"
        );
        let (event, (_, seq)) = s.publish(a.clone()).unwrap();
        assert_eq!(seq, 1);
        assert!(event.unwrap().conflict_with.is_none());
        let mut randomized = a.clone();
        randomized.signature = *elementsplus_preconf::elements::secp256k1_zkp::Secp256k1::new()
            .sign_schnorr_with_aux_rand(
                &elementsplus_preconf::elements::secp256k1_zkp::Message::from_digest(
                    bond().digest(a.bond, a.txid),
                ),
                &common::key(2),
                &[9; 32],
            )
            .as_ref();
        assert_eq!(s.publish(randomized).unwrap().1, ("duplicate", 1));
        let conflict = s.publish(b.clone()).unwrap().0.unwrap();
        assert_eq!(conflict.conflict_with, Some(a.clone()));
        let third = receipt(collateral(), transfer(3).txid());
        assert_eq!(s.publish(third).unwrap().1, ("already_conflicted", 2));
        assert_eq!(s.head(), 2);
    }
    let s = store(&temp);
    assert_eq!(s.stream, stream);
    assert_eq!(s.head(), 2);
    assert_eq!(
        s.replay(Some(&Cursor {
            stream: stream.clone(),
            seq: 1
        }))
        .unwrap()
        .len(),
        1
    );
    assert!(s.replay(Some(&Cursor { stream, seq: 3 })).is_err());
    assert!(s
        .replay(Some(&Cursor {
            stream: "00".repeat(32),
            seq: 0
        }))
        .is_err());
    let conflict = &s.events[1];
    bond()
        .satisfy(
            &penalty_env(),
            &elementsplus_preconf::operator::penalty_action(
                &conflict.receipt,
                conflict.conflict_with.as_ref().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn journal_corruption_and_unknown_or_invalid_receipts_fail_closed() {
    let temp = Temp::new();
    let mut s = store(&temp);
    let (mut bad, _) = evidence();
    bad.signature[1] ^= 1;
    assert!(s.publish(bad).is_err());
    let mut other = collateral();
    other.vout += 1;
    assert!(s.publish(receipt(other, transfer(1).txid())).is_err());
    assert_eq!(s.head(), 0);
    s.publish(evidence().0).unwrap();
    drop(s);
    let good = std::fs::read(temp.journal()).unwrap();
    std::fs::write(temp.journal(), &good[..good.len() - 1]).unwrap();
    assert!(
        Store::open(&temp.journal(), profile()).is_err(),
        "torn tail"
    );
    let mut corrupted = String::from_utf8(good).unwrap();
    corrupted = corrupted.replace("\"seq\":1", "\"seq\":2");
    std::fs::write(temp.journal(), corrupted).unwrap();
    assert!(
        Store::open(&temp.journal(), profile()).is_err(),
        "sequence corruption"
    );
}

#[test]
fn cursor_tracker_rejects_gaps_wrong_profile_early_ready_and_invalid_signatures() {
    let p = profile();
    let stream = "ab".repeat(32);
    let begin = ServerMessage::Begin {
        profile: p.id.clone(),
        stream: stream.clone(),
        from: 0,
        through: 1,
    };
    let mut t = Tracker::default();
    t.process(&begin, &p).unwrap();
    assert!(!t.caught_up);
    assert!(t
        .process(
            &ServerMessage::CaughtUp {
                cursor: Cursor {
                    stream: stream.clone(),
                    seq: 1
                }
            },
            &p
        )
        .is_err());
    assert!(!t.caught_up);
    t.process(&begin, &p).unwrap();
    let event = Event {
        seq: 1,
        receipt: evidence().0,
        conflict_with: None,
    };
    t.process(
        &ServerMessage::Event {
            event: event.clone().into(),
        },
        &p,
    )
    .unwrap();
    let cursor = Cursor {
        stream: stream.clone(),
        seq: 1,
    };
    t.process(
        &ServerMessage::CaughtUp {
            cursor: cursor.clone(),
        },
        &p,
    )
    .unwrap();
    assert!(t.caught_up);
    t.disconnected();
    assert!(!t.caught_up);
    assert_eq!(t.cursor, Some(cursor));
    let resumed = ServerMessage::Begin {
        profile: p.id.clone(),
        stream: stream.clone(),
        from: 1,
        through: 1,
    };
    t.process(&resumed, &p).unwrap();
    t.process(
        &ServerMessage::CaughtUp {
            cursor: Cursor {
                stream: stream.clone(),
                seq: 1,
            },
        },
        &p,
    )
    .unwrap();
    let mut gap = event.clone();
    gap.seq = 3;
    assert!(t
        .process(&ServerMessage::Event { event: gap.into() }, &p)
        .is_err());
    assert!(!t.caught_up);
    let mut wrong_profile = Tracker::default();
    assert!(wrong_profile
        .process(
            &ServerMessage::Begin {
                profile: "00".repeat(32),
                stream,
                from: 0,
                through: 0
            },
            &p
        )
        .is_err());
    let mut invalid = Tracker::default();
    invalid.process(&begin, &p).unwrap();
    let mut forged = event;
    forged.receipt.signature[0] ^= 1;
    assert!(invalid
        .process(
            &ServerMessage::Event {
                event: forged.into()
            },
            &p
        )
        .is_err());
    assert_eq!(invalid.cursor.unwrap().seq, 0);
}

#[test]
fn profile_rejects_cross_chain_and_duplicate_collateral_or_principal() {
    for attack in 0..4 {
        let mut a = Session {
            bond: collateral(),
            config: config(),
        };
        let mut b = a.clone();
        b.bond.vout += 1;
        b.config.protected_output.vout += 1;
        match attack {
            0 => b.bond = a.bond,
            1 => b.config.protected_output = a.config.protected_output,
            2 => {
                b.config.genesis = common::config()
                    .protected_output
                    .txid
                    .to_string()
                    .parse()
                    .unwrap()
            }
            _ => a.bond = a.config.protected_output,
        }
        assert!(Profile {
            version: 1,
            sessions: vec![a, b]
        }
        .validate()
        .is_err());
    }
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn next(socket: &mut Socket) -> ServerMessage {
    timeout(Duration::from_secs(8), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Text(t) => return serde_json::from_str(&t).unwrap(),
                Message::Ping(_) | Message::Pong(_) => (),
                m => panic!("unexpected message {m:?}"),
            }
        }
    })
    .await
    .expect("WebSocket event timeout")
}
async fn subscribe(endpoint: &str, cursor: Option<Cursor>) -> Socket {
    let (mut socket, _) = connect_async(endpoint).await.unwrap();
    let m = ClientMessage::Subscribe {
        profile: profile().id.clone(),
        cursor,
    };
    socket
        .send(Message::text(serde_json::to_string(&m).unwrap()))
        .await
        .unwrap();
    socket
}
async fn sync(socket: &mut Socket) -> (Cursor, Vec<Event>) {
    let mut events = Vec::new();
    loop {
        match next(socket).await {
            ServerMessage::Begin { .. } | ServerMessage::Heartbeat { .. } => (),
            ServerMessage::Event { event } => events.push(*event),
            ServerMessage::CaughtUp { cursor } => return (cursor, events),
            m => panic!("unexpected {m:?}"),
        }
    }
}
async fn publish(socket: &mut Socket, receipt: Receipt) {
    socket
        .send(Message::text(
            serde_json::to_string(&ClientMessage::Publish { receipt }).unwrap(),
        ))
        .await
        .unwrap();
}
async fn event(socket: &mut Socket) -> Event {
    loop {
        match next(socket).await {
            ServerMessage::Event { event } => return *event,
            ServerMessage::Published { .. } | ServerMessage::Heartbeat { .. } => (),
            m => panic!("unexpected {m:?}"),
        }
    }
}
async fn launch(
    s: Store,
    config: ServerConfig,
) -> (
    String,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(serve(listener, s, config, async {
        let _ = stopped.await;
    }));
    (endpoint, stop, task)
}

#[tokio::test]
async fn live_receipts_peer_fanout_conflicts_and_reconnect_replay() {
    let ta = Temp::new();
    let tb = Temp::new();
    let (a, stopa, taska) = launch(store(&ta), ServerConfig::default()).await;
    let (b, stopb, taskb) = launch(
        store(&tb),
        ServerConfig {
            peers: vec![a.clone()],
            ..Default::default()
        },
    )
    .await;
    let mut wa = subscribe(&a, None).await;
    let (cursor, _) = sync(&mut wa).await;
    let mut wb = subscribe(&b, None).await;
    sync(&mut wb).await;
    let (first, second) = evidence();
    publish(&mut wa, first.clone()).await;
    assert_eq!(event(&mut wa).await.receipt, first);
    assert_eq!(event(&mut wb).await.receipt, first);
    publish(&mut wb, second.clone()).await;
    assert_eq!(event(&mut wa).await.conflict_with, Some(first.clone()));
    assert_eq!(event(&mut wb).await.conflict_with, Some(first));
    wa.close(None).await.unwrap();
    let mut resumed = subscribe(&a, Some(cursor)).await;
    let (cursor, events) = sync(&mut resumed).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].receipt, second);
    assert_eq!(cursor.seq, 2);
    stopa.send(()).unwrap();
    stopb.send(()).unwrap();
    taska.await.unwrap().unwrap();
    taskb.await.unwrap().unwrap();
    assert_eq!(store(&ta).events.len(), 2);
    assert_eq!(store(&tb).events.len(), 2);
}

#[tokio::test]
async fn websocket_origin_profile_and_cursor_controls() {
    let temp = Temp::new();
    let (url, stop, task) = launch(store(&temp), ServerConfig::default()).await;
    let mut request = url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("origin", "https://untrusted.invalid".parse().unwrap());
    assert!(connect_async(request).await.is_err());
    let mut socket = subscribe(
        &url,
        Some(Cursor {
            stream: "00".repeat(32),
            seq: 0,
        }),
    )
    .await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Error { .. }
    ));
    let (mut socket, _) = connect_async(&url).await.unwrap();
    socket
        .send(Message::text(
            serde_json::to_string(&ClientMessage::Subscribe {
                profile: "00".repeat(32),
                cursor: None,
            })
            .unwrap(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Error { .. }
    ));
    let mut socket = subscribe(&url, None).await;
    sync(&mut socket).await;
    let mut bad = evidence().0;
    bad.signature[3] ^= 1;
    publish(&mut socket, bad).await;
    loop {
        match next(&mut socket).await {
            ServerMessage::Heartbeat { .. } => (),
            ServerMessage::Error { .. } => break,
            m => panic!("forged receipt was not rejected: {m:?}"),
        }
    }
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(store(&temp).head(), 0);
}
