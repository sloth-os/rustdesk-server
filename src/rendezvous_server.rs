use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, SplitStream, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::{Encrypt, FramedStream, KxTranscript, KX_PARAMS_DOMAIN, KX_VERSION_LATEST},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration, MissedTickBehavior},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::{box_, sign};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i64 = 30_000;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
type TcpStreamSource = SplitStream<Framed<TcpStream, BytesCodec>>;
type WsSource = SplitStream<tokio_tungstenite::WebSocketStream<TcpStream>>;

enum Sink {
    TcpStream(TcpStreamSink),
    Ws(WsSink),
}

impl Sink {
    async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        match self {
            Sink::TcpStream(s) => s.send(bytes).await?,
            Sink::Ws(s) => s.send(tungstenite::Message::Binary(bytes)).await?,
        }
        Ok(())
    }
}

enum Source {
    TcpStream(TcpStreamSource),
    Ws(WsSource),
}

impl Source {
    /// The next data frame: `None` at end of stream, `Err` on a read failure.
    /// Non-data WebSocket frames are consumed here; tungstenite answers pings itself.
    async fn next_frame(&mut self) -> Option<ResultType<BytesMut>> {
        match self {
            Source::TcpStream(s) => s.next().await.map(|r| r.map_err(Into::into)),
            Source::Ws(s) => loop {
                match s.next().await {
                    Some(Ok(tungstenite::Message::Binary(bytes))) => {
                        return Some(Ok(BytesMut::from(&bytes[..])));
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => return None,
                    Some(Ok(_)) => continue,
                    Some(Err(err)) => return Some(Err(err.into())),
                }
            },
        }
    }
}

/// The write half of a connection, handed to whoever needs to deliver a message to
/// it. The connection task owns the sink and the cipher state and encrypts what
/// arrives here; being cloneable, it survives being sent to, so map entries outlive
/// individual deliveries and are only dropped when the connection closes. Bounded
/// with a capacity of [`MAX_CONN_QUEUE`]: a peer that stopped draining its socket
/// must not make the routers pile up memory on its behalf, so a full queue drops.
type ConnSender = mpsc::Sender<Bytes>;

type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
// A TCP-mediator client stops re-registering once its key is confirmed and only echoes
// the empty frames it receives, so the heartbeat has to come from this side. 15s stays
// well inside both the client's bail-out (keep_alive 60s * 3/2) and the connection read
// timeout below; every frame received in turn refreshes the peer's registration time.
const MEDIATOR_HEARTBEAT_SECS: u64 = 15;
const MEDIATOR_KEEP_ALIVE_SECS: i32 = 60;
// Nothing may sit silent on a connection for longer than this. It bounds the wait for
// any one frame — including the key-exchange reply, which the client may delay by
// fetching the server key first (it reads our offer with an 18s timeout) — and it is
// what reaps a mediator that stopped echoing the heartbeat.
const CONN_READ_TIMEOUT_MS: u64 = 30_000;
// Sanity bounds for routed ICE candidates; the frame bound already caps the message.
const MAX_ICE_SESSION_KEY_LEN: usize = 256;
const MAX_ICE_CANDIDATE_LEN: usize = 2048;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
const MAX_RELAY_UUID_LEN: usize = 128;

// The peer sends this uuid to whatever relay_server names, so keep control bytes out of it.
fn validate_relay_uuid(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_RELAY_UUID_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid relay UUID");
    }
    Ok(())
}

// A peer acknowledging a RequestRelay leaves both fields empty.
fn validate_relay_response(uuid: &str, relay_server: &str) -> Result<(), &'static str> {
    if uuid.is_empty() && relay_server.is_empty() {
        return Ok(());
    }
    validate_relay_uuid(uuid)
}

// The HTTP tunnel relays to the API server on loopback: the request frame is already
// capped by MAX_MESSAGE, and the response body is capped so a runaway origin cannot
// balloon the relayed frame. An origin that cannot answer inside the client's overall
// budget (CONNECT_TIMEOUT + READ_TIMEOUT) is cut off here first.
const MAX_HTTP_PROXY_BODY: usize = 16 << 20;
const HTTP_PROXY_TIMEOUT_MS: u64 = 25_000;
// Upper bound on queued outbound frames per connection before routed messages for it
// are dropped: a peer that stopped draining its socket must not make the routers pile
// up unbounded memory on its behalf.
const MAX_CONN_QUEUE: usize = 256;

/// Queue a message onto a connection task, which writes it out (and encrypts it, when
/// a key exchange completed) from its own loop. Never blocks: the routers deliver to
/// many connections from shared paths, so a connection whose queue is full — it has
/// stopped draining its socket — loses this message instead of stalling them.
#[inline]
fn send_to_conn(conn_tx: &ConnSender, msg: RendezvousMessage) {
    if let Ok(bytes) = msg.write_to_bytes() {
        match conn_tx.try_send(Bytes::from(bytes)) {
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::warn!("Dropping a message for a connection with a full queue");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                log::debug!("Dropping a message for a closed connection");
            }
            Ok(()) => {}
        }
    }
}

/// The server's key exchange offer: a fresh ephemeral X25519 keypair whose public key
/// is signed with the server key and — the high bit flags a server that signs —
/// accompanied by a signature over exactly those bytes plus the version (KxParams).
/// This is what the client's key exchange expects to read as the first frame.
fn build_kx_offer(
    sk: &sign::SecretKey,
) -> ResultType<(RendezvousMessage, box_::SecretKey, [u8; 32])> {
    let (eph_pk, eph_sk) = box_::gen_keypair();
    let mut pk = eph_pk.0;
    pk[31] |= 0x80;
    let params = KxParams {
        pk: pk.to_vec().into(),
        version: KX_VERSION_LATEST,
        ..Default::default()
    };
    let mut to_sign = KX_PARAMS_DOMAIN.to_vec();
    to_sign.extend_from_slice(&params.write_to_bytes()?);
    let mut ex = KeyExchange::new();
    ex.keys = vec![sign::sign(&pk, sk).into()];
    ex.version = KX_VERSION_LATEST;
    ex.signed_params = sign::sign(&to_sign, sk).into();
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(ex);
    Ok((msg, eph_sk, pk))
}

/// Completes the exchange from the client's reply: unseal the shared secretbox key and
/// build the connection's cipher state. The server is the responder — it sends under the
/// responder subkey and receives under the initiator's — while a version-0 client uses
/// one key in both directions. A single `Encrypt` carries both directions' keys and
/// counters, mirroring the client's own instance.
fn complete_kx(
    ex: &KeyExchange,
    eph_sk: &box_::SecretKey,
    responder_pk: &[u8; 32],
) -> ResultType<Encrypt> {
    if ex.keys.len() != 2 {
        bail!("key exchange reply carries {} keys", ex.keys.len());
    }
    let picked = ex.version;
    if picked > KX_VERSION_LATEST {
        bail!("key exchange reply picked an unknown version {}", picked);
    }
    let key = Encrypt::decode(&ex.keys[1], &ex.keys[0], eph_sk)?;
    let enc = if picked == 0 {
        Encrypt::new(key)
    } else {
        Encrypt::new_split(
            key,
            false,
            &KxTranscript {
                initiator_pk: &ex.keys[0],
                responder_pk,
                advertised: KX_VERSION_LATEST,
                picked,
            },
        )?
    };
    Ok(enc)
}

/// Headers that belong to a single transport connection; the tunnel terminates them on
/// both sides and lets reqwest derive its own.
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The tunnel can only append an absolute path to a fixed loopback origin: reject
/// anything that does not start with a single '/', carries control characters, or is
/// over-long, so no request line can shift the destination or smuggle a second one.
fn validate_proxy_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 8192
        && path.starts_with('/')
        && !path.starts_with("//")
        && path.bytes().all(|b| b >= b' ' && b != 0x7f)
}

fn allowed_proxy_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
    )
}

// An online query for about 5000 ids is the largest message a client sends here.
const DEFAULT_MAX_MESSAGE_KB: usize = 64;
// A knob that can be turned to unbounded is not a bound.
const MAX_MESSAGE_KB_CAP: usize = 64 << 10;
// tungstenite's default, so raising MAX_MESSAGE_KB does not widen a frame past it.
const WS_DEFAULT_MAX_FRAME_SIZE: usize = 16 << 20;
// Every connection pays its read buffer up front, and tungstenite's default is 128 KiB.
const WS_BUFFER_SIZE: usize = 8 << 10;
static MAX_MESSAGE: Lazy<usize> =
    Lazy::new(|| max_message_kb(&get_arg("MAX_MESSAGE_KB")) << 10);

fn max_message_kb(arg: &str) -> usize {
    match arg.parse::<usize>() {
        Ok(kb) if kb > 0 => kb.min(MAX_MESSAGE_KB_CAP),
        _ => DEFAULT_MAX_MESSAGE_KB,
    }
}

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 { return; }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        if lock.len() >= max { lock.pop_front(); }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
    /// Loopback origin of the API server (the rendezvous port minus two), the only
    /// destination the HTTP proxy tunnel forwards to.
    api_origin: String,
}

#[derive(Clone)]
pub struct RendezvousServer {
    /// Punch sockets by address: a requester keeps its socket across the whole punch
    /// sequence and the WebRTC ICE trickle after it, so entries are only removed when
    /// the connection closes.
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, ConnSender>>>,
    /// Write halves of the TCP-mediator connections, by peer id. A peer registered
    /// over TCP has no usable UDP address, so messages routed to it go through here.
    mediators: Arc<Mutex<HashMap<String, ConnSender>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            mediators: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
                api_origin: format!("http://127.0.0.1:{}", port - 2),
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(bind_addr, port).await?;
        let mut listener2 = create_tcp_listener(bind_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(bind_addr, ws_port).await?;
        let mut listener_console = listen_console(bind_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        log::info!("MAX_MESSAGE_KB={}", *MAX_MESSAGE >> 10);
        let test_addr = get_arg("TEST_HBBS");
        if get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(bind_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        // Safety net for the connection-task cleanup: a connection that died without
        // unwinding (panic) leaves its entries behind, and a closed channel is the only
        // signal that survives it. The first tick fires at startup with nothing to sweep.
        let mut timer_sweep = interval(Duration::from_secs(MEDIATOR_HEARTBEAT_SECS));
        timer_sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = timer_sweep.tick() => {
                    self.mediators.lock().await.retain(|_, tx| !tx.is_closed());
                    self.tcp_punch.lock().await.retain(|_, tx| !tx.is_closed());
                }
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        _key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return Ok(());
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    } else if !self.check_ip_blocker(&ip, &id).await {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    log::warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id,
                                        ip,
                                        rk.pk,
                                        peer.info.ip,
                                        peer.pk,
                                    );
                                    drop(peer);
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                log::warn!(
                                    "Peer {} uuid mismatch: {:?} vs {:?}",
                                    id,
                                    rk.uuid,
                                    peer.uuid
                                );
                                drop(peer);
                                return send_rk_res(socket, addr, UUID_MISMATCH).await;
                            }
                            let ip_changed = peer.info.ip != ip;
                            (
                                peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                                ip_changed,
                            )
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if ip_changed {
                        let mut lock = IP_CHANGES.lock().await;
                        if let Some((tm, ips)) = lock.get_mut(&id) {
                            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                                *tm = Instant::now();
                                ips.clear();
                                ips.insert(ip.clone(), 1);
                            } else if let Some(v) = ips.get_mut(&ip) {
                                *v += 1;
                            } else {
                                ips.insert(ip.clone(), 1);
                            }
                        } else {
                            lock.insert(
                                id.clone(),
                                (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                            );
                        }
                    }
                    if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?
                }
                Some(rendezvous_message::Union::PunchHoleRequest(_)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(_)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(_)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        conn_tx: &ConnSender,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        mediator_id: &mut Option<String>,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // Register the punch socket for the whole punch sequence and the ICE
                    // trickle after it; the entry stays until the connection closes.
                    self.tcp_punch
                        .lock()
                        .await
                        .insert(try_into_v4(addr), conn_tx.clone());
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    if let Err(err) = validate_relay_uuid(&rf.uuid) {
                        log::warn!(
                            "Drop RequestRelay from {addr}: {err} (length {})",
                            rf.uuid.len()
                        );
                        return false;
                    }
                    self.tcp_punch
                        .lock()
                        .await
                        .insert(try_into_v4(addr), conn_tx.clone());
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    if let Err(err) = validate_relay_response(&rr.uuid, &rr.relay_server) {
                        log::warn!(
                            "Drop RelayResponse from {addr}: {err} (length {})",
                            rr.uuid.len()
                        );
                        return false;
                    }
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    // A's request socket stays registered, so keep the entry rather
                    // than removing it after this one delivery.
                    self.send_to_tcp(msg_out, addr_b).await;
                    return true;
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr).await);
                    return true;
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr).await);
                    return true;
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    send_to_conn(conn_tx, msg_out);
                    return true;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    self.handle_register_pk(rk, conn_tx, addr, mediator_id).await;
                    return true;
                }
                Some(rendezvous_message::Union::IceCandidate(ic)) => {
                    allow_err!(self.handle_ice_candidate(ic).await);
                    return true;
                }
                Some(rendezvous_message::Union::HttpProxyRequest(req)) => {
                    self.handle_http_proxy_request(req, conn_tx.clone()).await;
                    return true;
                }
                _ => {}
            }
        }
        // A long-lived connection (mediator, punch or proxy) survives messages it does
        // not know; the read timeout closes it if the peer goes silent.
        true
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent(&mut self, phs: PunchHoleSent, addr: SocketAddr) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!("punch hole response to {:?} from {:?}", &addr_a, &addr);
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id.clone()).await,
            relay_server: phs.relay_server.clone(),
            socket_addr_v6: phs.socket_addr_v6.clone(),
            upnp_port: phs.upnp_port,
            webrtc_sdp_answer: phs.webrtc_sdp_answer.clone(),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        self.send_to_tcp(msg_out, addr_a).await;
        Ok(())
    }

    #[inline]
    async fn handle_local_addr(&mut self, la: LocalAddr, addr: SocketAddr) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!("local addrs response to {:?} from {:?}", &addr_a, &addr);
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id.clone()).await,
            relay_server: la.relay_server,
            socket_addr_v6: la.socket_addr_v6,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        self.send_to_tcp(msg_out, addr_a).await;
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<String>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }

            // record punch hole request (from addr -> peer id/peer_addr)
            record_punch_req(
                try_into_v4(addr).ip().to_string(),
                try_into_v4(peer_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    socket_addr_v6: ph.socket_addr_v6,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    udp_port: ph.udp_port,
                    force_relay: ph.force_relay,
                    upnp_port: ph.upnp_port,
                    socket_addr_v6: ph.socket_addr_v6,
                    webrtc_sdp_offer: ph.webrtc_sdp_offer,
                    ..Default::default()
                });
            }
            // The message is routed to B by id: over its TCP-mediator conn when it
            // registered one, else to the UDP address it registered from.
            Ok((msg_out, Some(id)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    /// Queue a message onto a peer's registered punch socket. The entry is kept — a
    /// requester holds its socket across the whole punch sequence and the ICE trickle
    /// after it — and dies with the connection.
    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        if let Some(conn_tx) = self.tcp_punch.lock().await.get(&try_into_v4(addr)).cloned() {
            send_to_conn(&conn_tx, msg);
        } else {
            log::debug!("No punch socket for {:?}", addr);
        }
    }

    /// Deliver a message to a peer by id: its TCP-mediator connection when it registered
    /// one, otherwise its registered UDP address.
    #[inline]
    async fn send_to_peer(&mut self, id: String, msg: RendezvousMessage) {
        if let Some(conn_tx) = self.mediators.lock().await.get(&id).cloned() {
            send_to_conn(&conn_tx, msg);
        } else if let Some(peer) = self.pm.get_in_memory(&id).await {
            let peer_addr = peer.read().await.socket_addr;
            self.tx.send(Data::Msg(msg.into(), peer_addr)).ok();
        } else {
            log::debug!("No route to peer {}", id);
        }
    }

    /// Refresh a mediator's registration: every frame it sends proves it is alive, and
    /// the freshness check of a punch request at it reads this.
    #[inline]
    async fn touch_mediator(&self, id: &str) {
        if let Some(peer) = self.pm.get_in_memory(id).await {
            peer.write().await.last_reg_time = Instant::now();
        }
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_id) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        match to_id {
            Some(id) => self.send_to_peer(id, msg).await,
            None => self.send_to_tcp(msg, addr).await,
        }
        Ok(())
    }

    /// Route a WebRTC ICE candidate: the controlled peer addresses it to the controller
    /// by id, the controller returns candidates on its punch socket by the return route
    /// its request arrived on.
    #[inline]
    async fn handle_ice_candidate(&mut self, ic: IceCandidate) -> ResultType<()> {
        if ic.session_key.is_empty()
            || ic.session_key.len() > MAX_ICE_SESSION_KEY_LEN
            || ic.candidate.is_empty()
            || ic.candidate.len() > MAX_ICE_CANDIDATE_LEN
        {
            bail!(
                "invalid ice candidate (session_key {} bytes, candidate {} bytes)",
                ic.session_key.len(),
                ic.candidate.len()
            );
        }
        if !ic.id.is_empty() {
            self.send_to_peer(
                ic.id.clone(),
                RendezvousMessage {
                    union: Some(rendezvous_message::Union::IceCandidate(ic)),
                    ..Default::default()
                },
            )
            .await;
            return Ok(());
        }
        let addr = AddrMangle::decode(&ic.socket_addr);
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_ice_candidate(ic);
        self.send_to_tcp(msg_out, addr).await;
        Ok(())
    }

    /// RegisterPk over TCP: a full registration (with pk) makes this connection the
    /// peer's TCP mediator — messages routed to it then travel here, kept alive by a
    /// heartbeat, while its liveness keeps refreshing the peer's registration. An empty
    /// pk is the id-change probe of the client UI (`check_id`): it only asks whether the
    /// new id is available, and renames the record when it is.
    async fn handle_register_pk(
        &mut self,
        rk: RegisterPk,
        conn_tx: &ConnSender,
        addr: SocketAddr,
        mediator_id: &mut Option<String>,
    ) {
        let id = rk.id.clone();
        if rk.pk.is_empty() {
            self.handle_check_id(rk, conn_tx, addr).await;
            return;
        }
        if rk.uuid.is_empty() || rk.id.is_empty() {
            // Neither register nor probe; not an error worth a reply.
            return;
        }
        let ip = addr.ip().to_string();
        if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
            send_rk_res_tcp(conn_tx, UUID_MISMATCH, 0);
            return;
        } else if !self.check_ip_blocker(&ip, &id).await {
            send_rk_res_tcp(conn_tx, TOO_FREQUENT, 0);
            return;
        }
        let peer = self.pm.get_or(&id).await;
        let (changed, ip_changed) = {
            let peer = peer.read().await;
            if peer.uuid.is_empty() {
                (true, false)
            } else {
                if peer.uuid == rk.uuid {
                    if peer.info.ip != ip && peer.pk != rk.pk {
                        log::warn!(
                            "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                            id,
                            ip,
                            rk.pk,
                            peer.info.ip,
                            peer.pk,
                        );
                        drop(peer);
                        send_rk_res_tcp(conn_tx, UUID_MISMATCH, 0);
                        return;
                    }
                } else {
                    log::warn!(
                        "Peer {} uuid mismatch: {:?} vs {:?}",
                        id,
                        rk.uuid,
                        peer.uuid
                    );
                    drop(peer);
                    send_rk_res_tcp(conn_tx, UUID_MISMATCH, 0);
                    return;
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                    ip_changed,
                )
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if req_pk.0 > 2 {
            send_rk_res_tcp(conn_tx, TOO_FREQUENT, 0);
            return;
        }
        req_pk.0 += 1;
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.clone(), 1);
                } else if let Some(v) = ips.get_mut(&ip) {
                    *v += 1;
                } else {
                    ips.insert(ip.clone(), 1);
                }
            } else {
                lock.insert(
                    id.clone(),
                    (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                );
            }
        }
        if changed {
            let res = self
                .pm
                .update_pk(id.clone(), peer, addr, rk.uuid, rk.pk, ip)
                .await;
            if res != register_pk_response::Result::OK {
                send_rk_res_tcp(conn_tx, res, 0);
                return;
            }
        } else {
            // Unchanged pk still has to make this connection the peer's live
            // registration: a TCP mediator has no other register flow.
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.last_reg_time = Instant::now();
        }
        send_rk_res_tcp(
            conn_tx,
            register_pk_response::Result::OK,
            MEDIATOR_KEEP_ALIVE_SECS,
        );
        self.mediators.lock().await.insert(id.clone(), conn_tx.clone());
        *mediator_id = Some(id);
    }

    /// The empty-pk RegisterPk of `check_id`: the client UI asks whether an id is
    /// available (old_id empty) or renames its record to a new id (old_id set). The
    /// uuid must own the old record, and the new id must not belong to anyone else.
    async fn handle_check_id(&mut self, rk: RegisterPk, conn_tx: &ConnSender, addr: SocketAddr) {
        if rk.uuid.is_empty() || rk.id.is_empty() {
            return;
        }
        let ip = addr.ip().to_string();
        if rk.id.len() < 6 || rk.id.len() > MAX_PEER_ID_LEN {
            send_rk_res_tcp(conn_tx, register_pk_response::Result::INVALID_ID_FORMAT, 0);
            return;
        }
        if !self.check_ip_blocker(&ip, &rk.id).await {
            send_rk_res_tcp(conn_tx, TOO_FREQUENT, 0);
            return;
        }
        if rk.old_id.is_empty() {
            // Availability probe: an id taken by another uuid is not available.
            let res = match self.pm.get(&rk.id).await {
                Some(peer) => {
                    if peer.read().await.uuid.is_empty() {
                        register_pk_response::Result::OK
                    } else {
                        register_pk_response::Result::ID_EXISTS
                    }
                }
                None => register_pk_response::Result::OK,
            };
            send_rk_res_tcp(conn_tx, res, 0);
            return;
        }
        let res = self.rename_id(&rk).await;
        send_rk_res_tcp(conn_tx, res, 0);
    }

    /// Rebinds a peer's record to its new id: the uuid must own the old record, the new
    /// id must be free, then the database row and any in-memory entry both move so
    /// routing and freshness checks follow immediately.
    async fn rename_id(&mut self, rk: &RegisterPk) -> register_pk_response::Result {
        let Some(old) = self.pm.get(&rk.old_id).await else {
            return register_pk_response::Result::UUID_MISMATCH;
        };
        let (guid, uuid, pk, info_str) = {
            let r = old.read().await;
            (
                r.guid.clone(),
                r.uuid.clone(),
                r.pk.clone(),
                serde_json::to_string(&r.info).unwrap_or_default(),
            )
        };
        if guid.is_empty() || uuid.is_empty() || uuid != rk.uuid {
            return register_pk_response::Result::UUID_MISMATCH;
        }
        if let Some(owned) = self.pm.get(&rk.id).await {
            if !owned.read().await.uuid.is_empty() {
                return register_pk_response::Result::ID_EXISTS;
            }
        }
        if let Err(err) = self.pm.db.update_pk(&guid, &rk.id, &pk, &info_str).await {
            log::error!("db.update_pk failed: {}", err);
            return register_pk_response::Result::SERVER_ERROR;
        }
        self.pm.move_peer(&rk.old_id, &rk.id).await;
        register_pk_response::Result::OK
    }

    /// Forward an HttpProxyRequest to the API server on loopback: the client tunnels
    /// its API calls through hbbs when it can only reach the rendezvous port. The
    /// destination is fixed, the path is validated above, and the whole exchange is
    /// time- and size-bounded, so a hung or runaway origin cannot pin the task or the
    /// connection.
    async fn handle_http_proxy_request(&self, req: HttpProxyRequest, conn_tx: ConnSender) {
        if !allowed_proxy_method(&req.method) {
            log::warn!("HttpProxyRequest with a disallowed method: {}", req.method);
            send_http_proxy_error(&conn_tx, "Unsupported method");
            return;
        }
        if !validate_proxy_path(&req.path) {
            log::warn!("HttpProxyRequest with an invalid path ({} bytes)", req.path.len());
            send_http_proxy_error(&conn_tx, "Invalid path");
            return;
        }
        let url = format!("{}{}", self.inner.api_origin, req.path);
        let origin = self.inner.api_origin.clone();
        tokio::spawn(async move {
            let resp = Self::proxy_request(req, url, origin).await;
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_http_proxy_response(resp);
            send_to_conn(&conn_tx, msg_out);
        });
    }

    async fn proxy_request(
        req: HttpProxyRequest,
        url: String,
        origin: String,
    ) -> HttpProxyResponse {
        let mut resp = HttpProxyResponse::new();
        let method = match req.method.parse::<reqwest::Method>() {
            Ok(m) => m,
            Err(_) => {
                resp.error = format!("Invalid method: {}", req.method);
                return resp;
            }
        };
        let client = match reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(HTTP_PROXY_TIMEOUT_MS))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                resp.error = format!("Failed to build client: {}", err);
                return resp;
            }
        };
        let _ = origin;
        let mut request = client.request(method, &url);
        for h in req.headers.iter() {
            let name = h.name.to_ascii_lowercase();
            if is_hop_by_hop_header(&name) || name == "host" || name == "content-length" {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(h.name.as_bytes()),
                reqwest::header::HeaderValue::from_str(&h.value),
            ) {
                request = request.header(name, value);
            }
        }
        if !req.body.is_empty() {
            request = request.body(req.body.to_vec());
        }
        let Ok(mut response) = request.send().await else {
            resp.error = format!("Failed to reach {}", origin);
            return resp;
        };
        resp.status = response.status().as_u16() as i32;
        for (name, value) in response.headers().iter() {
            if is_hop_by_hop_header(name.as_str()) {
                continue;
            }
            if let Ok(value) = value.to_str() {
                resp.headers.push(HeaderEntry {
                    name: name.as_str().to_owned(),
                    value: value.to_owned(),
                    ..Default::default()
                });
            }
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > MAX_HTTP_PROXY_BODY {
                        resp.error = format!(
                            "The response exceeds {} bytes",
                            MAX_HTTP_PROXY_BODY
                        );
                        return resp;
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(err) => {
                    resp.error = format!("Failed to read the body: {}", err);
                    return resp;
                }
            }
        }
        resp.body = body.into();
        resp
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// Handles loopback console requests and external NAT or online-status queries.
    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        if let Err(err) = timeout(1000, stream.write_all(res.as_bytes()))
                            .await
                            .unwrap_or_else(|elapsed| Err(elapsed.into()))
                        {
                            log::warn!("Failed to send the console reply: {err}");
                        }
                    }
                }
            });
            return;
        }
        let mut stream = FramedStream::from(stream, addr);
        stream.codec_mut().set_max_packet_length(*MAX_MESSAGE);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    /// Processes rendezvous messages on an accepted TCP or WebSocket connection.
    ///
    /// The connection task is the sole writer: everything anyone wants to say to this
    /// peer goes through its channel, so frames never interleave and encryption, once a
    /// key exchange completed, is applied in order. A fresh non-WebSocket connection is
    /// offered a key exchange as the very first frame; the first inbound frame then
    /// decides the mode — a `KeyExchange` reply encrypts the stream, anything else is a
    /// client from before the exchange and is processed in the clear. WebSocket skips
    /// the exchange: wss already encrypts the transport.
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (mut sink, mut source) = if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let callback = |req: &Request, response: Response| {
                let headers = req.headers();
                // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
                // client IP is preserved when the WebSocket port runs behind a
                // reverse proxy (WSS). They are NOT validated: anyone who can reach
                // this port directly can spoof an arbitrary IP, bypassing IP-based
                // rate limiting / blocking and corrupting logged IPs. Do not expose
                // the WebSocket port directly to untrusted networks; only the
                // reverse proxy, which overwrites these headers, should be able to
                // connect to it.
                // https://github.com/rustdesk/rustdesk-server/issues/634
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok());
                if let Some(ip) = real_ip {
                    if let Ok(ip) = ip.parse() {
                        addr = SocketAddr::new(ip, addr.port());
                    }
                }
                Ok(response)
            };
            let ws_config = tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(*MAX_MESSAGE))
                .max_frame_size(Some((*MAX_MESSAGE).min(WS_DEFAULT_MAX_FRAME_SIZE)))
                .read_buffer_size(WS_BUFFER_SIZE)
                .write_buffer_size(WS_BUFFER_SIZE);
            let ws_stream = timeout(
                30_000,
                tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config)),
            )
            .await??;
            let (a, b) = ws_stream.split();
            (Sink::Ws(a), Source::Ws(b))
        } else {
            let mut framed = Framed::new(stream, BytesCodec::new());
            framed.codec_mut().set_max_packet_length(*MAX_MESSAGE);
            let (a, b) = framed.split();
            (Sink::TcpStream(a), Source::TcpStream(b))
        };

        let (conn_tx, mut conn_rx) = mpsc::channel::<Bytes>(MAX_CONN_QUEUE);

        // The offer, gated on having a server key like the signed-pk paths. A client
        // that cannot answer it reads the frame, does not recognize it, and carries
        // on in the clear; the first inbound frame below tells the two apart.
        let mut kx = None;
        if !ws {
            if let Some(sk) = self.inner.sk.as_ref() {
                match build_kx_offer(sk) {
                    Ok((msg, eph_sk, responder_pk)) => match msg.write_to_bytes() {
                        Ok(bytes) => {
                            if let Err(err) = sink.send_bytes(Bytes::from(bytes)).await {
                                log::debug!(
                                    "Failed to send the key exchange offer to {:?}: {}",
                                    addr,
                                    err
                                );
                                self.tcp_punch.lock().await.remove(&try_into_v4(addr));
                                log::debug!("Tcp connection from {:?} closed", addr);
                                return Ok(());
                            }
                            kx = Some((eph_sk, responder_pk));
                        }
                        Err(err) => log::error!("Failed to encode the key exchange offer: {}", err),
                    },
                    Err(err) => log::error!("Failed to build the key exchange offer: {}", err),
                }
            }
        }

        let mut enc: Option<Encrypt> = None;
        let mut mediator_id: Option<String> = None;
        // A mediator's keep-alive comes from this side, as an empty frame the client
        // echoes back; the echo refreshes the registration. The first tick fires
        // before any registration, as a no-op, and a delayed tick skips rather than
        // bursts after a long inline proxy request has held the loop.
        let mut timer_heartbeat = interval(Duration::from_secs(MEDIATOR_HEARTBEAT_SECS));
        timer_heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                res = timeout(CONN_READ_TIMEOUT_MS, source.next_frame()) => {
                    let mut bytes = match res {
                        Ok(Some(Ok(bytes))) => bytes,
                        Ok(Some(Err(err))) => {
                            log::debug!("Read failure on connection {:?}: {}", addr, err);
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            log::debug!("Read timeout on connection {:?}", addr);
                            break;
                        }
                    };
                    if let Some(enc) = enc.as_mut() {
                        if let Err(err) = enc.dec(&mut bytes) {
                            log::warn!("Decryption failure on connection {:?}: {}", addr, err);
                            break;
                        }
                    }
                    if let Some((eph_sk, responder_pk)) = kx.take() {
                        // Only the very first frame can answer the offer. A reply
                        // switches to encrypted mode and is not a rendezvous
                        // message; anything else falls through as the client's
                        // first plaintext message.
                        if let Ok(msg) = RendezvousMessage::parse_from_bytes(&bytes) {
                            if let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union {
                                match complete_kx(&ex, &eph_sk, &responder_pk) {
                                    Ok(e) => {
                                        enc = Some(e);
                                        log::info!("Connection secured for {:?}", addr);
                                        continue;
                                    }
                                    Err(err) => {
                                        log::warn!(
                                            "Key exchange with {:?} failed: {}",
                                            addr,
                                            err
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if let Some(id) = mediator_id.as_ref() {
                        self.touch_mediator(id).await;
                    }
                    if !self.handle_tcp(&bytes, &conn_tx, addr, key, ws, &mut mediator_id).await {
                        break;
                    }
                }
                Some(bytes) = conn_rx.recv() => {
                    let bytes = if let Some(enc) = enc.as_mut() {
                        Bytes::from(enc.enc(&bytes))
                    } else {
                        bytes
                    };
                    if let Err(err) = sink.send_bytes(bytes).await {
                        log::debug!("Write failure on connection {:?}: {}", addr, err);
                        break;
                    }
                }
                _ = timer_heartbeat.tick() => {
                    if let Some(id) = mediator_id.as_ref() {
                        if let Err(mpsc::error::TrySendError::Full(_)) =
                            conn_tx.try_send(Bytes::new())
                        {
                            log::warn!("Heartbeat to mediator {} dropped: full queue", id);
                        }
                    }
                }
            }
        }

        // Whatever this connection registered under goes with it. The mediator entry is
        // only removed when it is still ours: a reconnecting peer has already replaced
        // it with its own channel, and that one must survive.
        self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        if let Some(id) = mediator_id.as_ref() {
            let mut mediators = self.mediators.lock().await;
            let mine = mediators
                .get(id)
                .map(|tx| tx.same_channel(&conn_tx))
                .unwrap_or(false);
            if mine {
                mediators.remove(id);
            }
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

/// RegisterPkResponse for a TCP/WebSocket connection: queued onto the connection task
/// rather than written inline, so it is encrypted when a key exchange completed and
/// never interleaves with another frame. `keep_alive` tells the client how often it
/// must send to keep its registration alive.
#[inline]
fn send_rk_res_tcp(conn_tx: &ConnSender, res: register_pk_response::Result, keep_alive: i32) {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        keep_alive,
        ..Default::default()
    });
    send_to_conn(conn_tx, msg_out);
}

/// HttpProxyResponse carrying only an error string, for the paths that fail before or
/// during the proxied request.
#[inline]
fn send_http_proxy_error(conn_tx: &ConnSender, error: &str) {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_http_proxy_response(HttpProxyResponse {
        error: error.to_owned(),
        ..Default::default()
    });
    send_to_conn(conn_tx, msg_out);
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_message_kb_falls_back_to_default_and_is_capped() {
        assert_eq!(max_message_kb(""), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("0"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("abc"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("256"), 256);
        assert_eq!(max_message_kb(&usize::MAX.to_string()), MAX_MESSAGE_KB_CAP);
    }

    #[test]
    fn default_message_bound_holds_an_online_query_for_5000_ids() {
        let mut msg = RendezvousMessage::new();
        msg.set_online_request(OnlineRequest {
            id: "1234567890".to_owned(),
            peers: (0..5000).map(|i| format!("{i:010}")).collect(),
            ..Default::default()
        });
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len <= DEFAULT_MAX_MESSAGE_KB << 10, "{len}");
    }

    #[test]
    fn relay_uuid_validation() {
        let uuid = "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12";
        assert_eq!(validate_relay_response(uuid, "relay.example"), Ok(()));
        assert_eq!(validate_relay_response("", ""), Ok(()));
        let max_len = "a".repeat(128);
        for value in [
            uuid,
            "E4C181D0-41C7-4AE6-8EF0-36581B6B2B12",
            "e4c181d041c74ae68ef036581b6b2b12",
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "a_b-c",
            max_len.as_str(),
        ] {
            assert_eq!(validate_relay_uuid(value), Ok(()), "rejected {value:?}");
        }
        let too_long = "a".repeat(129);
        for value in [
            "",
            "\r\nPING\r\n",
            "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12\n",
            "e4c181d0 41c7",
            "{e4c181d0-41c7-4ae6-8ef0-36581b6b2b12}",
            "e4c181d0\0",
            "é",
            too_long.as_str(),
        ] {
            assert!(validate_relay_uuid(value).is_err(), "accepted {value:?}");
            assert!(validate_relay_response(value, "relay.example").is_err());
        }
    }

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // one request at least, so MAX_PUNCH_REQUESTS=0 is exercised too
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // the oldest half is evicted and the newest kept
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }
}
