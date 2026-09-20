//! Local WebSocket service; expose through an authenticated/TLS reverse proxy.
use super::{ClientMessage, Cursor, Event, ServerMessage, Store, Tracker, MAX_FRAME};
use crate::operator::Receipt;
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::VecDeque,
    future::Future,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{broadcast, Semaphore},
    task::JoinSet,
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    tungstenite::{
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
        Message,
    },
    WebSocketStream,
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT: Duration = Duration::from_secs(3);
const MAX_CONNECTIONS: usize = 32;
const MAX_PUBLISH_PER_SECOND: u32 = 32;

#[derive(Default)]
pub struct ServerConfig {
    /// Browser origins must be explicit; absent Origin is allowed for native peers.
    pub allowed_origins: Vec<String>,
    /// Administrative allowlist; no peer discovery from untrusted messages.
    pub peers: Vec<String>,
}

#[derive(Clone)]
struct Hub {
    store: Arc<Mutex<Store>>,
    changes: broadcast::Sender<Result<Event, ()>>,
}
struct Snapshot {
    profile: String,
    cursor: Cursor,
    events: Vec<Event>,
    changes: broadcast::Receiver<Result<Event, ()>>,
}
impl Hub {
    fn snapshot(&self, cursor: Option<&Cursor>) -> Result<Snapshot, String> {
        // Subscribe and take the high-water mark under the same lock used to
        // append/publish. An event cannot fall between snapshot and live tail.
        let store = self.store.lock().map_err(|_| "store unavailable")?;
        let changes = self.changes.subscribe();
        let events = store.replay(cursor)?;
        Ok(Snapshot {
            profile: store.profile.id.clone(),
            cursor: Cursor {
                stream: store.stream.clone(),
                seq: store.head(),
            },
            events,
            changes,
        })
    }
    async fn publish(&self, receipt: Receipt) -> Result<ServerMessage, String> {
        let hub = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = hub.store.lock().map_err(|_| "store unavailable")?;
            match store.publish(receipt) {
                Ok((event, (status, seq))) => {
                    // Durable append before broadcast, still inside the lock:
                    // concurrent publishers cannot reorder the sequence.
                    if let Some(event) = event {
                        let _ = hub.changes.send(Ok(event));
                    }
                    Ok(ServerMessage::Published {
                        seq,
                        status: status.into(),
                    })
                }
                Err(error) => {
                    if store.failed {
                        let _ = hub.changes.send(Err(()));
                    }
                    Err(error)
                }
            }
        })
        .await
        .map_err(|_| "publish task failed")?
    }
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME))
}
async fn send<S>(socket: &mut WebSocketStream<S>, message: &ServerMessage) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let text = serde_json::to_string(message).map_err(|_| "serialization failed")?;
    timeout(IO_TIMEOUT, socket.send(Message::text(text)))
        .await
        .map_err(|_| "slow connection")?
        .map_err(|_| "connection closed".into())
}
fn parse_client(message: Message) -> Result<Option<ClientMessage>, String> {
    match message {
        Message::Text(text) if text.len() <= MAX_FRAME => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| "invalid client message".into()),
        Message::Ping(_) | Message::Pong(_) => Ok(None),
        _ => Err("expected bounded JSON text".into()),
    }
}

async fn subscription<S>(socket: &mut WebSocketStream<S>, hub: &Hub) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let first = timeout(IO_TIMEOUT, socket.next())
        .await
        .map_err(|_| "subscribe timeout")?
        .ok_or("connection closed")?
        .map_err(|_| "bad WebSocket frame")?;
    let Some(ClientMessage::Subscribe { profile, cursor }) = parse_client(first)? else {
        return Err("first message must subscribe".into());
    };
    let mut snapshot = hub.snapshot(cursor.as_ref())?;
    if profile != snapshot.profile {
        return Err("profile mismatch".into());
    }
    send(
        socket,
        &ServerMessage::Begin {
            profile,
            stream: snapshot.cursor.stream.clone(),
            from: cursor.as_ref().map_or(0, |c| c.seq),
            through: snapshot.cursor.seq,
        },
    )
    .await?;
    for event in snapshot.events {
        send(
            socket,
            &ServerMessage::Event {
                event: event.into(),
            },
        )
        .await?;
    }
    let mut sent = snapshot.cursor;
    send(
        socket,
        &ServerMessage::CaughtUp {
            cursor: sent.clone(),
        },
    )
    .await?;
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rate_since = Instant::now();
    let mut publishes = 0;
    loop {
        tokio::select! {
            change = snapshot.changes.recv() => {
                let event = change.map_err(|_| "live stream gap; reconnect with cursor")?
                    .map_err(|_| "journal unavailable")?;
                if event.seq != sent.seq + 1 { return Err("live stream gap".into()); }
                sent.seq = event.seq;
                send(socket, &ServerMessage::Event { event: event.into() }).await?;
            }
            message = socket.next() => {
                let message = message.ok_or("connection closed")?.map_err(|_| "bad WebSocket frame")?;
                match parse_client(message)? {
                    Some(ClientMessage::Publish { receipt }) => {
                        if rate_since.elapsed() >= Duration::from_secs(1) { rate_since = Instant::now(); publishes = 0; }
                        publishes += 1;
                        if publishes > MAX_PUBLISH_PER_SECOND { return Err("publish rate exceeded".into()); }
                        let reply = hub.publish(receipt).await?;
                        send(socket, &reply).await?;
                    }
                    Some(ClientMessage::Subscribe { .. }) => return Err("already subscribed".into()),
                    None => (),
                }
            }
            _ = heartbeat.tick() => {
                // Last SENT cursor, not the store's head: pending live events
                // must not look like a sequence gap to a correct subscriber.
                if hub.store.lock().map_err(|_| "store unavailable")?.failed { return Err("journal unavailable".into()); }
                send(socket, &ServerMessage::Heartbeat { cursor: sent.clone() }).await?;
            }
        }
    }
}

fn validate_peer(peer: &str) -> Result<(), String> {
    let url = url::Url::parse(peer).map_err(|_| "invalid peer URL")?;
    let local = url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !(url.scheme() == "wss" || (url.scheme() == "ws" && local))
    {
        return Err(
            "peers require wss (or numeric loopback ws), without URL credentials/fragments".into(),
        );
    }
    Ok(())
}

async fn peer_session(hub: &Hub, endpoint: &str, tracker: &mut Tracker) -> Result<(), String> {
    let (mut socket, _) = timeout(
        IO_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(endpoint, Some(websocket_config()), false),
    )
    .await
    .map_err(|_| "peer connect timeout")?
    .map_err(|_| "peer connection failed")?;
    let mut snapshot = hub.snapshot(None)?;
    let profile = hub
        .store
        .lock()
        .map_err(|_| "store unavailable")?
        .profile
        .clone();
    let subscribe = ClientMessage::Subscribe {
        profile: profile.id.clone(),
        cursor: tracker.cursor.clone(),
    };
    timeout(
        IO_TIMEOUT,
        socket.send(Message::text(serde_json::to_string(&subscribe).unwrap())),
    )
    .await
    .map_err(|_| "peer write timeout")?
    .map_err(|_| "peer closed")?;
    let mut pending: VecDeque<Receipt> = snapshot.events.into_iter().map(|e| e.receipt).collect();
    let mut last_received = Instant::now();
    let mut timer = tokio::time::interval(HEARTBEAT);
    // Outgoing receipt pacing stays below the same service's per-connection
    // rate limit even when exchanging a full snapshot at reconnect.
    let mut publish_tick = tokio::time::interval(Duration::from_millis(50));
    publish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            message = socket.next() => {
                let message = message.ok_or("peer closed")?.map_err(|_| "peer read failed")?;
                match message {
                    Message::Text(text) if text.len() <= MAX_FRAME => {
                        let response: ServerMessage = serde_json::from_str(&text).map_err(|_| "bad peer message")?;
                        let mut next = tracker.clone();
                        if let Some(receipt) = next.process(&response, &profile)? {
                            hub.publish(receipt).await?;
                            if let ServerMessage::Event { event } = &response {
                                if let Some(other) = &event.conflict_with { hub.publish(other.clone()).await?; }
                            }
                        }
                        // Advance peer cursor only AFTER durable local ingestion.
                        *tracker = next;
                        if !matches!(response, ServerMessage::Published { .. }) { last_received = Instant::now(); }
                    }
                    Message::Ping(_) | Message::Pong(_) => (),
                    _ => return Err("invalid peer frame".into()),
                }
            }
            change = snapshot.changes.recv() => {
                let event = change.map_err(|_| "peer fell behind")?.map_err(|_| "journal unavailable")?;
                if pending.len() >= super::MAX_SESSIONS * 2 { return Err("peer queue exceeded".into()); }
                pending.push_back(event.receipt);
            }
            _ = publish_tick.tick(), if !pending.is_empty() => {
                let message = ClientMessage::Publish { receipt: pending.pop_front().unwrap() };
                timeout(IO_TIMEOUT, socket.send(Message::text(serde_json::to_string(&message).unwrap()))).await
                    .map_err(|_| "peer write timeout")?.map_err(|_| "peer write failed")?;
            }
            _ = timer.tick() => {
                if last_received.elapsed() >= IO_TIMEOUT { return Err("peer stale".into()); }
            }
        }
    }
}

/// No live node mutation. Shutdown stops connections and peer tasks; committed
/// receipts remain in the journal. A relay's health is NOT a payment guarantee.
pub async fn serve(
    listener: TcpListener,
    store: Store,
    config: ServerConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    if !listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .ip()
        .is_loopback()
    {
        return Err("bind loopback only; use a TLS/auth reverse proxy for remote access".into());
    }
    if config.peers.len() > 8 || config.allowed_origins.len() > 16 {
        return Err("too many configured peers/origins".into());
    }
    for peer in &config.peers {
        validate_peer(peer)?;
    }
    if config
        .allowed_origins
        .iter()
        .any(|o| o == "*" || o == "null" || o.len() > 256)
    {
        return Err("origins must be explicit trusted browser origins".into());
    }
    let (changes, _) = broadcast::channel(super::MAX_SESSIONS * 2);
    let hub = Hub {
        store: Arc::new(Mutex::new(store)),
        changes,
    };
    let mut tasks = JoinSet::new();
    for (index, endpoint) in config.peers.into_iter().enumerate() {
        let hub = hub.clone();
        tasks.spawn(async move {
            let mut tracker = Tracker::default();
            let mut delay = Duration::from_secs(1);
            loop {
                if let Err(reason) = peer_session(&hub, &endpoint, &mut tracker).await {
                    // Only a configured index and our fixed error text, never
                    // endpoint credentials, untrusted messages or raw receipts.
                    eprintln!("peer {index} unavailable: {reason}; reconnecting");
                }
                tracker.disconnected();
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(15));
            }
        });
    }
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let origins = Arc::new(config.allowed_origins);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tasks.join_next(), if !tasks.is_empty() => (),
            accepted = listener.accept() => {
                let (tcp, _) = accepted.map_err(|e| e.to_string())?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let hub = hub.clone();
                let origins = origins.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    // Tungstenite's Callback requires an unboxed ErrorResponse.
                    #[allow(clippy::result_large_err)]
                    let callback = move |request: &Request, response: Response| {
                        let origin = request.headers().get("origin");
                        if origin.is_some_and(|o| !origins.iter().any(|allowed| o.as_bytes() == allowed.as_bytes())) {
                            let mut rejection = tokio_tungstenite::tungstenite::http::Response::new(Some("origin denied".into()));
                            *rejection.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN;
                            return Err(rejection);
                        }
                        Ok(response)
                    };
                    let Ok(Ok(mut socket)) = timeout(IO_TIMEOUT, tokio_tungstenite::accept_hdr_async_with_config(
                        tcp, callback, Some(websocket_config()))).await else { return; };
                    if let Err(reason) = subscription(&mut socket, &hub).await {
                        let _ = send(&mut socket, &ServerMessage::Error { reason }).await;
                    }
                    let _ = timeout(IO_TIMEOUT, socket.close(None)).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
