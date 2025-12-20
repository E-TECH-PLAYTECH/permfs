// PermFS Network Transport — TCP-based cluster communication

#![cfg(feature = "network")]

use crate::sync::{Arc, Mutex, RwLock};
use crate::{AllocError, BlockAddr, ClusterTransport, FsResult, IoError, BLOCK_SIZE};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

pub const PROTOCOL_VERSION: u32 = 1;
pub const PROTOCOL_MAGIC: u32 = 0x50464E54; // "PFNT"
pub const DEFAULT_PORT: u16 = 7432;
pub const MAX_MESSAGE_SIZE: usize = BLOCK_SIZE + 256;
const MAX_WIRE_SIZE: usize = MAX_MESSAGE_SIZE + MessageHeader::SIZE;
pub const CONNECTION_TIMEOUT_MS: u64 = 5000;
pub const READ_TIMEOUT_MS: u64 = 10000;
pub const WRITE_TIMEOUT_MS: u64 = 10000;
pub const MAX_RETRY_ATTEMPTS: u32 = 3;
pub const RETRY_DELAY_MS: u64 = 100;
const HANDSHAKE_MAGIC: u32 = 0x50464853; // "PFHS"
const HANDSHAKE_VERSION: u32 = 1;
const HANDSHAKE_NONCE_SIZE: usize = 32;
type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// MESSAGE TYPES
// ============================================================================

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    // Block operations
    ReadBlock = 0x0001,
    WriteBlock = 0x0002,
    AllocBlock = 0x0003,
    FreeBlock = 0x0004,

    // Responses
    ReadReply = 0x0101,
    WriteAck = 0x0102,
    AllocReply = 0x0103,
    FreeAck = 0x0104,
    Error = 0x01FF,

    // Cluster management
    Ping = 0x0200,
    Pong = 0x0201,
    NodeJoin = 0x0210,
    NodeLeave = 0x0211,
}

impl MessageType {
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(Self::ReadBlock),
            0x0002 => Some(Self::WriteBlock),
            0x0003 => Some(Self::AllocBlock),
            0x0004 => Some(Self::FreeBlock),
            0x0101 => Some(Self::ReadReply),
            0x0102 => Some(Self::WriteAck),
            0x0103 => Some(Self::AllocReply),
            0x0104 => Some(Self::FreeAck),
            0x01FF => Some(Self::Error),
            0x0200 => Some(Self::Ping),
            0x0201 => Some(Self::Pong),
            0x0210 => Some(Self::NodeJoin),
            0x0211 => Some(Self::NodeLeave),
            _ => None,
        }
    }
}

// ============================================================================
// MESSAGE HEADER
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MessageHeader {
    pub magic: u32,
    pub version: u32,
    pub msg_type: u16,
    pub flags: u16,
    pub payload_len: u32,
    pub request_id: u64,
    pub source_node: u64,
    pub dest_node: u64,
}

impl MessageHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(msg_type: MessageType, source: u64, dest: u64, payload_len: u32) -> Self {
        Self {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            msg_type: msg_type as u16,
            flags: 0,
            payload_len,
            request_id: 0,
            source_node: source,
            dest_node: dest,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..10].copy_from_slice(&self.msg_type.to_le_bytes());
        buf[10..12].copy_from_slice(&self.flags.to_le_bytes());
        buf[12..16].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[16..24].copy_from_slice(&self.request_id.to_le_bytes());
        buf[24..32].copy_from_slice(&self.source_node.to_le_bytes());
        buf[32..40].copy_from_slice(&self.dest_node.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Self {
        Self {
            magic: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            version: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            msg_type: u16::from_le_bytes(buf[8..10].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[10..12].try_into().unwrap()),
            payload_len: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            request_id: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            source_node: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            dest_node: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == PROTOCOL_MAGIC && self.version == PROTOCOL_VERSION
    }
}

// ============================================================================
// NODE REGISTRY
// ============================================================================

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub node_id: u64,
    pub address: SocketAddr,
    pub last_seen: u64,
    pub is_healthy: bool,
    pub auth: NodeAuthConfig,
}

pub struct NodeRegistry {
    nodes: RwLock<HashMap<u64, NodeInfo>>,
    local_node_id: u64,
}

#[derive(Clone, Debug)]
struct HandshakeRequest {
    source_node: u64,
    dest_node: u64,
    key_id: u32,
    nonce: [u8; HANDSHAKE_NONCE_SIZE],
    mac: [u8; 32],
}

impl HandshakeRequest {
    const SIZE: usize = 4 + 4 + 8 + 8 + 4 + HANDSHAKE_NONCE_SIZE + 32;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.source_node.to_le_bytes());
        buf[16..24].copy_from_slice(&self.dest_node.to_le_bytes());
        buf[24..28].copy_from_slice(&self.key_id.to_le_bytes());
        buf[28..28 + HANDSHAKE_NONCE_SIZE].copy_from_slice(&self.nonce);
        buf[28 + HANDSHAKE_NONCE_SIZE..].copy_from_slice(&self.mac);
        buf
    }

    fn signing_data(&self) -> [u8; Self::SIZE - 32] {
        let mut buf = [0u8; Self::SIZE - 32];
        buf[0..4].copy_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.source_node.to_le_bytes());
        buf[16..24].copy_from_slice(&self.dest_node.to_le_bytes());
        buf[24..28].copy_from_slice(&self.key_id.to_le_bytes());
        buf[28..].copy_from_slice(&self.nonce);
        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Option<Self> {
        let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        let version = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        if magic != HANDSHAKE_MAGIC || version != HANDSHAKE_VERSION {
            return None;
        }
        let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        nonce.copy_from_slice(&buf[28..28 + HANDSHAKE_NONCE_SIZE]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[28 + HANDSHAKE_NONCE_SIZE..]);

        Some(Self {
            source_node: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            dest_node: u64::from_le_bytes(buf[16..24].try_into().ok()?),
            key_id: u32::from_le_bytes(buf[24..28].try_into().ok()?),
            nonce,
            mac,
        })
    }
}

#[derive(Clone, Debug)]
struct HandshakeResponse {
    server_node: u64,
    client_node: u64,
    key_id: u32,
    client_nonce: [u8; HANDSHAKE_NONCE_SIZE],
    server_nonce: [u8; HANDSHAKE_NONCE_SIZE],
    mac: [u8; 32],
}

impl HandshakeResponse {
    const SIZE: usize = 4 + 4 + 8 + 8 + 4 + (HANDSHAKE_NONCE_SIZE * 2) + 32;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.server_node.to_le_bytes());
        buf[16..24].copy_from_slice(&self.client_node.to_le_bytes());
        buf[24..28].copy_from_slice(&self.key_id.to_le_bytes());
        buf[28..28 + HANDSHAKE_NONCE_SIZE].copy_from_slice(&self.client_nonce);
        buf[28 + HANDSHAKE_NONCE_SIZE..28 + (HANDSHAKE_NONCE_SIZE * 2)]
            .copy_from_slice(&self.server_nonce);
        buf[28 + (HANDSHAKE_NONCE_SIZE * 2)..].copy_from_slice(&self.mac);
        buf
    }

    fn signing_data(&self) -> [u8; Self::SIZE - 32] {
        let mut buf = [0u8; Self::SIZE - 32];
        buf[0..4].copy_from_slice(&HANDSHAKE_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.server_node.to_le_bytes());
        buf[16..24].copy_from_slice(&self.client_node.to_le_bytes());
        buf[24..28].copy_from_slice(&self.key_id.to_le_bytes());
        buf[28..28 + HANDSHAKE_NONCE_SIZE].copy_from_slice(&self.client_nonce);
        buf[28 + HANDSHAKE_NONCE_SIZE..28 + (HANDSHAKE_NONCE_SIZE * 2)]
            .copy_from_slice(&self.server_nonce);
        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Option<Self> {
        let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        let version = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        if magic != HANDSHAKE_MAGIC || version != HANDSHAKE_VERSION {
            return None;
        }
        let mut client_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        client_nonce.copy_from_slice(&buf[28..28 + HANDSHAKE_NONCE_SIZE]);
        let mut server_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        server_nonce
            .copy_from_slice(&buf[28 + HANDSHAKE_NONCE_SIZE..28 + (HANDSHAKE_NONCE_SIZE * 2)]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[28 + (HANDSHAKE_NONCE_SIZE * 2)..]);

        Some(Self {
            server_node: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            client_node: u64::from_le_bytes(buf[16..24].try_into().ok()?),
            key_id: u32::from_le_bytes(buf[24..28].try_into().ok()?),
            client_nonce,
            server_nonce,
            mac,
        })
    }
}

fn compute_mac(secret: &[u8], data: &[u8]) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Some(out)
}

#[derive(Clone, Debug)]
pub struct SharedSecret {
    pub key_id: u32,
    pub secret: Vec<u8>,
}

impl SharedSecret {
    pub fn new(key_id: u32, secret: Vec<u8>) -> Self {
        Self { key_id, secret }
    }
}

#[derive(Clone, Debug)]
pub struct NodeAuthConfig {
    pub primary: SharedSecret,
    pub rollover: Option<SharedSecret>,
}

impl NodeAuthConfig {
    pub fn new(primary: SharedSecret) -> Self {
        Self {
            primary,
            rollover: None,
        }
    }

    pub fn with_rollover(primary: SharedSecret, rollover: SharedSecret) -> Self {
        Self {
            primary,
            rollover: Some(rollover),
        }
    }

    fn candidates(&self) -> impl Iterator<Item = &SharedSecret> {
        std::iter::once(&self.primary).chain(self.rollover.iter())
    }

    pub fn select(&self, key_id: u32) -> Option<SharedSecret> {
        self.candidates().find(|s| s.key_id == key_id).cloned()
    }
}

impl NodeRegistry {
    pub fn new(local_node_id: u64) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            local_node_id,
        }
    }

    pub fn register(&self, node_id: u64, address: SocketAddr, auth: NodeAuthConfig) {
        let mut nodes = self.nodes.write();
        nodes.insert(
            node_id,
            NodeInfo {
                node_id,
                address,
                last_seen: 0,
                is_healthy: true,
                auth,
            },
        );
    }

    pub fn update_auth(&self, node_id: u64, auth: NodeAuthConfig) {
        let mut nodes = self.nodes.write();
        if let Some(info) = nodes.get_mut(&node_id) {
            info.auth = auth;
        }
    }

    pub fn unregister(&self, node_id: u64) {
        let mut nodes = self.nodes.write();
        nodes.remove(&node_id);
    }

    pub fn get(&self, node_id: u64) -> Option<NodeInfo> {
        let nodes = self.nodes.read();
        nodes.get(&node_id).cloned()
    }

    pub fn secrets_for(&self, node_id: u64) -> Option<NodeAuthConfig> {
        let nodes = self.nodes.read();
        nodes.get(&node_id).map(|n| n.auth.clone())
    }

    pub fn primary_secret(&self, node_id: u64) -> Option<SharedSecret> {
        self.secrets_for(node_id).map(|cfg| cfg.primary)
    }

    pub fn mark_healthy(&self, node_id: u64, healthy: bool) {
        let mut nodes = self.nodes.write();
        if let Some(info) = nodes.get_mut(&node_id) {
            info.is_healthy = healthy;
        }
    }

    pub fn update_last_seen(&self, node_id: u64, timestamp: u64) {
        let mut nodes = self.nodes.write();
        if let Some(info) = nodes.get_mut(&node_id) {
            info.last_seen = timestamp;
        }
    }

    pub fn all_healthy(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read();
        nodes
            .values()
            .filter(|n| n.is_healthy && n.node_id != self.local_node_id)
            .cloned()
            .collect()
    }
}

// ============================================================================
// CONNECTION POOL
// ============================================================================

struct PooledConnection {
    stream: TcpStream,
    peer_id: u64,
    last_used: std::time::Instant,
}

pub struct ConnectionPool {
    connections: Mutex<HashMap<u64, Vec<PooledConnection>>>,
    max_per_node: usize,
    idle_timeout: Duration,
}

impl ConnectionPool {
    pub fn new(max_per_node: usize, idle_timeout_secs: u64) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            max_per_node,
            idle_timeout: Duration::from_secs(idle_timeout_secs),
        }
    }

    pub fn get(&self, node_id: u64) -> Option<TcpStream> {
        let mut pool = self.connections.lock();
        if let Some(conns) = pool.get_mut(&node_id) {
            while let Some(conn) = conns.pop() {
                if conn.last_used.elapsed() < self.idle_timeout {
                    if conn.peer_id != node_id {
                        continue;
                    }
                    if let Ok(stream) = conn.stream.try_clone() {
                        return Some(stream);
                    }
                }
            }
        }
        None
    }

    pub fn put(&self, node_id: u64, stream: TcpStream) {
        let mut pool = self.connections.lock();
        let conns = pool.entry(node_id).or_insert_with(Vec::new);

        // Prune old connections
        conns.retain(|c| c.last_used.elapsed() < self.idle_timeout);

        if conns.len() < self.max_per_node {
            conns.push(PooledConnection {
                stream,
                peer_id: node_id,
                last_used: std::time::Instant::now(),
            });
        }
    }

    pub fn remove(&self, node_id: u64) {
        let mut pool = self.connections.lock();
        pool.remove(&node_id);
    }
}

// ============================================================================
// TCP TRANSPORT
// ============================================================================

pub struct TcpTransport {
    local_node_id: u64,
    registry: Arc<NodeRegistry>,
    pool: Arc<ConnectionPool>,
    next_request_id: AtomicU64,
    running: AtomicBool,
}

impl TcpTransport {
    pub fn new(local_node_id: u64) -> Self {
        Self {
            local_node_id,
            registry: Arc::new(NodeRegistry::new(local_node_id)),
            pool: Arc::new(ConnectionPool::new(4, 60)),
            next_request_id: AtomicU64::new(1),
            running: AtomicBool::new(true),
        }
    }

    pub fn registry(&self) -> &Arc<NodeRegistry> {
        &self.registry
    }

    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn open_stream(&self, address: SocketAddr) -> Result<TcpStream, IoError> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|_| IoError::IoFailed)?;

        socket.set_nodelay(true).ok();
        socket.set_keepalive(true).ok();

        let sock_addr = SockAddr::from(address);
        socket
            .connect_timeout(&sock_addr, Duration::from_millis(CONNECTION_TIMEOUT_MS))
            .map_err(|_| IoError::NetworkTimeout)?;

        let stream: TcpStream = socket.into();
        stream
            .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)))
            .ok();
        Ok(stream)
    }

    fn perform_client_handshake_with_secret(
        &self,
        node_id: u64,
        stream: &mut TcpStream,
        secret: &SharedSecret,
    ) -> Result<(), IoError> {
        let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut req = HandshakeRequest {
            source_node: self.local_node_id,
            dest_node: node_id,
            key_id: secret.key_id,
            nonce,
            mac: [0u8; 32],
        };
        req.mac =
            compute_mac(&secret.secret, &req.signing_data()).ok_or(IoError::PermissionDenied)?;
        stream
            .write_all(&req.to_bytes())
            .map_err(|_| IoError::NetworkTimeout)?;
        stream.flush().map_err(|_| IoError::NetworkTimeout)?;

        let mut resp_buf = [0u8; HandshakeResponse::SIZE];
        stream
            .read_exact(&mut resp_buf)
            .map_err(|_| IoError::PermissionDenied)?;
        let resp = HandshakeResponse::from_bytes(&resp_buf).ok_or(IoError::PermissionDenied)?;

        if resp.client_node != self.local_node_id
            || resp.server_node != node_id
            || resp.key_id != secret.key_id
            || resp.client_nonce != nonce
        {
            return Err(IoError::PermissionDenied);
        }

        let expected_mac =
            compute_mac(&secret.secret, &resp.signing_data()).ok_or(IoError::PermissionDenied)?;
        if expected_mac != resp.mac {
            return Err(IoError::PermissionDenied);
        }

        Ok(())
    }

    fn connect(&self, node_id: u64) -> Result<TcpStream, IoError> {
        // Try pool first
        if let Some(stream) = self.pool.get(node_id) {
            return Ok(stream);
        }

        // Get node address
        let info = self.registry.get(node_id).ok_or(IoError::NetworkTimeout)?;

        if !info.is_healthy {
            return Err(IoError::NetworkTimeout);
        }

        let auth_cfg = self
            .registry
            .secrets_for(node_id)
            .ok_or(IoError::PermissionDenied)?;

        for secret in auth_cfg.candidates() {
            if let Ok(mut stream) = self.open_stream(info.address) {
                if self
                    .perform_client_handshake_with_secret(node_id, &mut stream, secret)
                    .is_ok()
                {
                    return Ok(stream);
                }
            }
        }

        Err(IoError::PermissionDenied)
    }

    fn send_request(
        &self,
        node_id: u64,
        header: &MessageHeader,
        payload: &[u8],
    ) -> Result<TcpStream, IoError> {
        if payload.len() + MessageHeader::SIZE > MAX_WIRE_SIZE {
            return Err(IoError::Corrupted);
        }
        if header.payload_len as usize != payload.len() {
            return Err(IoError::Corrupted);
        }

        let mut stream = self.connect(node_id)?;

        let header_bytes = header.to_bytes();
        stream
            .write_all(&header_bytes)
            .map_err(|_| IoError::IoFailed)?;

        if !payload.is_empty() {
            stream.write_all(payload).map_err(|_| IoError::IoFailed)?;
        }

        stream.flush().map_err(|_| IoError::IoFailed)?;

        Ok(stream)
    }

    fn recv_response(
        &self,
        stream: &mut TcpStream,
        expected_source: u64,
    ) -> Result<(MessageHeader, Vec<u8>), IoError> {
        let mut header_buf = [0u8; MessageHeader::SIZE];
        stream
            .read_exact(&mut header_buf)
            .map_err(|_| IoError::NetworkTimeout)?;

        let header = MessageHeader::from_bytes(&header_buf);
        if !header.is_valid() {
            return Err(IoError::Corrupted);
        }
        if header.source_node != expected_source || header.dest_node != self.local_node_id {
            return Err(IoError::PermissionDenied);
        }

        let payload_len = header.payload_len as usize;
        let msg_type = MessageType::from_u16(header.msg_type);
        if payload_len + MessageHeader::SIZE > MAX_WIRE_SIZE {
            return Err(IoError::Corrupted);
        }
        if payload_len == 0
            && matches!(
                msg_type,
                Some(MessageType::ReadReply) | Some(MessageType::AllocReply)
            )
        {
            return Err(IoError::Corrupted);
        }

        let mut fixed_buf = [0u8; MAX_MESSAGE_SIZE];
        let payload = if payload_len > 0 {
            let slice = &mut fixed_buf[..payload_len];
            stream
                .read_exact(slice)
                .map_err(|_| IoError::NetworkTimeout)?;
            slice.to_vec()
        } else {
            Vec::new()
        };

        Ok((header, payload))
    }

    fn execute_with_retry<F, R>(&self, node_id: u64, mut op: F) -> Result<R, IoError>
    where
        F: FnMut(&Self, u64) -> Result<R, IoError>,
    {
        let mut last_err = IoError::NetworkTimeout;

        for attempt in 0..MAX_RETRY_ATTEMPTS {
            match op(self, node_id) {
                Ok(result) => {
                    self.registry.mark_healthy(node_id, true);
                    return Ok(result);
                }
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < MAX_RETRY_ATTEMPTS {
                        self.pool.remove(node_id);
                        std::thread::sleep(Duration::from_millis(
                            RETRY_DELAY_MS * (attempt as u64 + 1),
                        ));
                    }
                }
            }
        }

        self.registry.mark_healthy(node_id, false);
        Err(last_err)
    }
}

impl ClusterTransport for TcpTransport {
    fn read_remote(&self, node: u64, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        self.execute_with_retry(node, |this, node_id| {
            let addr_bytes = addr.to_bytes();
            let mut header = MessageHeader::new(
                MessageType::ReadBlock,
                this.local_node_id,
                node_id,
                32, // BlockAddr size
            );
            header.request_id = this.next_request_id();

            let mut stream = this.send_request(node_id, &header, &addr_bytes)?;
            let (resp_header, payload) = this.recv_response(&mut stream, node_id)?;

            let msg_type = MessageType::from_u16(resp_header.msg_type);
            match msg_type {
                Some(MessageType::ReadReply) => {
                    if payload.len() != BLOCK_SIZE {
                        return Err(IoError::Corrupted);
                    }
                    buf.copy_from_slice(&payload);
                    this.pool.put(node_id, stream);
                    Ok(())
                }
                Some(MessageType::Error) => Err(IoError::IoFailed),
                _ => Err(IoError::Corrupted),
            }
        })
    }

    fn write_remote(&self, node: u64, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        self.execute_with_retry(node, |this, node_id| {
            let mut payload = Vec::with_capacity(32 + BLOCK_SIZE);
            payload.extend_from_slice(&addr.to_bytes());
            payload.extend_from_slice(buf);

            let mut header = MessageHeader::new(
                MessageType::WriteBlock,
                this.local_node_id,
                node_id,
                payload.len() as u32,
            );
            header.request_id = this.next_request_id();

            let mut stream = this.send_request(node_id, &header, &payload)?;
            let (resp_header, _) = this.recv_response(&mut stream, node_id)?;

            let msg_type = MessageType::from_u16(resp_header.msg_type);
            match msg_type {
                Some(MessageType::WriteAck) => {
                    this.pool.put(node_id, stream);
                    Ok(())
                }
                Some(MessageType::Error) => Err(IoError::IoFailed),
                _ => Err(IoError::Corrupted),
            }
        })
    }

    fn alloc_remote(&self, node: u64, volume: u32) -> Result<BlockAddr, AllocError> {
        self.execute_with_retry(node, |this, node_id| {
            let payload = volume.to_le_bytes();
            let mut header =
                MessageHeader::new(MessageType::AllocBlock, this.local_node_id, node_id, 4);
            header.request_id = this.next_request_id();

            let mut stream = this
                .send_request(node_id, &header, &payload)
                .map_err(|_| IoError::NetworkTimeout)?;
            let (resp_header, resp_payload) = this
                .recv_response(&mut stream, node_id)
                .map_err(|_| IoError::NetworkTimeout)?;

            let msg_type = MessageType::from_u16(resp_header.msg_type);
            match msg_type {
                Some(MessageType::AllocReply) => {
                    if resp_payload.len() != 32 {
                        return Err(IoError::Corrupted);
                    }
                    let addr = BlockAddr::from_bytes(resp_payload[0..32].try_into().unwrap());
                    if addr.is_null() {
                        return Err(IoError::IoFailed);
                    }
                    this.pool.put(node_id, stream);
                    Ok(addr)
                }
                Some(MessageType::Error) => Err(IoError::IoFailed),
                _ => Err(IoError::Corrupted),
            }
        })
        .map_err(|_| AllocError::NetworkError)
    }

    fn free_remote(&self, node: u64, addr: BlockAddr) -> Result<(), AllocError> {
        self.execute_with_retry(node, |this, node_id| {
            let payload = addr.to_bytes();
            let mut header =
                MessageHeader::new(MessageType::FreeBlock, this.local_node_id, node_id, 32);
            header.request_id = this.next_request_id();

            let mut stream = this
                .send_request(node_id, &header, &payload)
                .map_err(|_| IoError::NetworkTimeout)?;
            let (resp_header, _) = this
                .recv_response(&mut stream, node_id)
                .map_err(|_| IoError::NetworkTimeout)?;

            let msg_type = MessageType::from_u16(resp_header.msg_type);
            match msg_type {
                Some(MessageType::FreeAck) => {
                    this.pool.put(node_id, stream);
                    Ok(())
                }
                Some(MessageType::Error) => Err(IoError::IoFailed),
                _ => Err(IoError::Corrupted),
            }
        })
        .map_err(|_| AllocError::NetworkError)
    }
}

// ============================================================================
// SERVER
// ============================================================================

/// Request handler trait for server-side processing
pub trait RequestHandler: Send + Sync {
    fn handle_read(&self, addr: BlockAddr) -> Result<[u8; BLOCK_SIZE], IoError>;
    fn handle_write(&self, addr: BlockAddr, data: &[u8; BLOCK_SIZE]) -> Result<(), IoError>;
    fn handle_alloc(&self, volume: u32) -> Result<BlockAddr, AllocError>;
    fn handle_free(&self, addr: BlockAddr) -> Result<(), AllocError>;
}

pub struct TcpServer {
    local_node_id: u64,
    listener: TcpListener,
    running: Arc<AtomicBool>,
    registry: Arc<NodeRegistry>,
}

impl TcpServer {
    pub fn bind(
        local_node_id: u64,
        addr: SocketAddr,
        registry: Arc<NodeRegistry>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;

        Ok(Self {
            local_node_id,
            listener,
            running: Arc::new(AtomicBool::new(true)),
            registry,
        })
    }

    pub fn run<H: RequestHandler + 'static>(&self, handler: Arc<H>) {
        while self.running.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let handler = Arc::clone(&handler);
                    let node_id = self.local_node_id;
                    let registry = Arc::clone(&self.registry);
                    std::thread::spawn(move || {
                        Self::handle_connection(node_id, registry, stream, handler);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    }

    fn handle_connection<H: RequestHandler>(
        local_node_id: u64,
        registry: Arc<NodeRegistry>,
        mut stream: TcpStream,
        handler: Arc<H>,
    ) {
        stream
            .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)))
            .ok();

        let authenticated_peer = match Self::accept_handshake(local_node_id, &registry, &mut stream)
        {
            Ok(peer_id) => peer_id,
            Err(_) => return,
        };

        loop {
            // Read header
            let mut header_buf = [0u8; MessageHeader::SIZE];
            if stream.read_exact(&mut header_buf).is_err() {
                break;
            }

            let header = MessageHeader::from_bytes(&header_buf);
            if !header.is_valid() {
                break;
            }

            if header.source_node != authenticated_peer || header.dest_node != local_node_id {
                let resp_header =
                    MessageHeader::new(MessageType::Error, local_node_id, header.source_node, 0);
                let _ = stream.write_all(&resp_header.to_bytes());
                let _ = stream.flush();
                break;
            }

            let msg_type = match MessageType::from_u16(header.msg_type) {
                Some(mt) => mt,
                None => break,
            };

            let payload_len = header.payload_len as usize;
            if payload_len + MessageHeader::SIZE > MAX_WIRE_SIZE {
                break;
            }

            let requires_payload = matches!(
                msg_type,
                MessageType::ReadBlock
                    | MessageType::WriteBlock
                    | MessageType::AllocBlock
                    | MessageType::FreeBlock
            );
            if payload_len == 0 && requires_payload {
                let resp_header =
                    MessageHeader::new(MessageType::Error, local_node_id, header.source_node, 0);
                let _ = stream.write_all(&resp_header.to_bytes());
                let _ = stream.flush();
                continue;
            }

            // Read payload
            let mut payload_buf = [0u8; MAX_MESSAGE_SIZE];
            if payload_len > 0 {
                if stream.read_exact(&mut payload_buf[..payload_len]).is_err() {
                    break;
                }
            }
            let payload = &payload_buf[..payload_len];

            // Process request
            let (resp_type, resp_payload) = match msg_type {
                MessageType::ReadBlock => {
                    if payload.len() != 32 {
                        (MessageType::Error, Vec::new())
                    } else {
                        let addr = BlockAddr::from_bytes(payload[0..32].try_into().unwrap());
                        match handler.handle_read(addr) {
                            Ok(data) => (MessageType::ReadReply, data.to_vec()),
                            Err(_) => (MessageType::Error, Vec::new()),
                        }
                    }
                }
                MessageType::WriteBlock => {
                    if payload.len() != 32 + BLOCK_SIZE {
                        (MessageType::Error, Vec::new())
                    } else {
                        let addr = BlockAddr::from_bytes(payload[0..32].try_into().unwrap());
                        let data: [u8; BLOCK_SIZE] = payload[32..].try_into().unwrap();
                        match handler.handle_write(addr, &data) {
                            Ok(()) => (MessageType::WriteAck, Vec::new()),
                            Err(_) => (MessageType::Error, Vec::new()),
                        }
                    }
                }
                MessageType::AllocBlock => {
                    if payload.len() != 4 {
                        (MessageType::Error, Vec::new())
                    } else {
                        let volume = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                        match handler.handle_alloc(volume) {
                            Ok(addr) => (MessageType::AllocReply, addr.to_bytes().to_vec()),
                            Err(_) => (MessageType::Error, Vec::new()),
                        }
                    }
                }
                MessageType::FreeBlock => {
                    if payload.len() != 32 {
                        (MessageType::Error, Vec::new())
                    } else {
                        let addr = BlockAddr::from_bytes(payload[0..32].try_into().unwrap());
                        match handler.handle_free(addr) {
                            Ok(()) => (MessageType::FreeAck, Vec::new()),
                            Err(_) => (MessageType::Error, Vec::new()),
                        }
                    }
                }
                MessageType::Ping => (MessageType::Pong, Vec::new()),
                _ => (MessageType::Error, Vec::new()),
            };

            // Send response
            let resp_header = MessageHeader::new(
                resp_type,
                local_node_id,
                header.source_node,
                resp_payload.len() as u32,
            );

            if stream.write_all(&resp_header.to_bytes()).is_err() {
                break;
            }
            if !resp_payload.is_empty() && stream.write_all(&resp_payload).is_err() {
                break;
            }
            if stream.flush().is_err() {
                break;
            }
        }
    }

    fn accept_handshake(
        local_node_id: u64,
        registry: &NodeRegistry,
        stream: &mut TcpStream,
    ) -> Result<u64, IoError> {
        let mut req_buf = [0u8; HandshakeRequest::SIZE];
        stream
            .read_exact(&mut req_buf)
            .map_err(|_| IoError::PermissionDenied)?;

        let request = HandshakeRequest::from_bytes(&req_buf).ok_or(IoError::PermissionDenied)?;

        if request.dest_node != local_node_id {
            return Err(IoError::PermissionDenied);
        }

        let auth_cfg = registry
            .secrets_for(request.source_node)
            .ok_or(IoError::PermissionDenied)?;
        let secret = auth_cfg
            .select(request.key_id)
            .ok_or(IoError::PermissionDenied)?;

        let expected_mac = compute_mac(&secret.secret, &request.signing_data())
            .ok_or(IoError::PermissionDenied)?;
        if expected_mac != request.mac {
            return Err(IoError::PermissionDenied);
        }

        let mut server_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut server_nonce);

        let mut response = HandshakeResponse {
            server_node: local_node_id,
            client_node: request.source_node,
            key_id: secret.key_id,
            client_nonce: request.nonce,
            server_nonce,
            mac: [0u8; 32],
        };

        response.mac = compute_mac(&secret.secret, &response.signing_data())
            .ok_or(IoError::PermissionDenied)?;

        stream
            .write_all(&response.to_bytes())
            .map_err(|_| IoError::PermissionDenied)?;
        stream.flush().map_err(|_| IoError::PermissionDenied)?;

        Ok(request.source_node)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct CountingHandler {
        read_calls: AtomicUsize,
        write_calls: AtomicUsize,
        alloc_calls: AtomicUsize,
        free_calls: AtomicUsize,
    }

    impl RequestHandler for CountingHandler {
        fn handle_read(&self, _addr: BlockAddr) -> Result<[u8; BLOCK_SIZE], IoError> {
            self.read_calls.fetch_add(1, Ordering::SeqCst);
            Ok([0u8; BLOCK_SIZE])
        }

        fn handle_write(&self, _addr: BlockAddr, _data: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn handle_alloc(&self, _volume: u32) -> Result<BlockAddr, AllocError> {
            self.alloc_calls.fetch_add(1, Ordering::SeqCst);
            Ok(BlockAddr::NULL)
        }

        fn handle_free(&self, _addr: BlockAddr) -> Result<(), AllocError> {
            self.free_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    const TEST_KEY_ID: u32 = 1;
    const TEST_SECRET: &[u8] = b"permfs-shared-secret-for-tests";

    fn test_auth_config() -> NodeAuthConfig {
        NodeAuthConfig::new(SharedSecret::new(TEST_KEY_ID, TEST_SECRET.to_vec()))
    }

    fn perform_test_handshake(stream: &mut TcpStream, source: u64, dest: u64) {
        let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut req = HandshakeRequest {
            source_node: source,
            dest_node: dest,
            key_id: TEST_KEY_ID,
            nonce,
            mac: [0u8; 32],
        };
        req.mac = compute_mac(TEST_SECRET, &req.signing_data()).unwrap();
        stream.write_all(&req.to_bytes()).unwrap();
        stream.flush().unwrap();

        let mut resp_buf = [0u8; HandshakeResponse::SIZE];
        stream.read_exact(&mut resp_buf).unwrap();
        let resp = HandshakeResponse::from_bytes(&resp_buf).unwrap();
        assert_eq!(resp.client_nonce, nonce);
        let expected = compute_mac(TEST_SECRET, &resp.signing_data()).unwrap();
        assert_eq!(expected, resp.mac);
    }

    #[test]
    fn test_message_header_roundtrip() {
        let header = MessageHeader::new(MessageType::ReadBlock, 123, 456, 100);
        let bytes = header.to_bytes();
        let recovered = MessageHeader::from_bytes(&bytes);

        let header_magic = header.magic;
        let header_msg = header.msg_type;
        let header_source = header.source_node;
        let header_dest = header.dest_node;
        let header_payload = header.payload_len;

        assert_eq!(header_magic, recovered.magic);
        assert_eq!(header_msg, recovered.msg_type);
        assert_eq!(header_source, recovered.source_node);
        assert_eq!(header_dest, recovered.dest_node);
        assert_eq!(header_payload, recovered.payload_len);
    }

    #[test]
    fn test_node_registry() {
        let registry = NodeRegistry::new(1);

        registry.register(2, "127.0.0.1:7432".parse().unwrap(), test_auth_config());
        registry.register(3, "127.0.0.1:7433".parse().unwrap(), test_auth_config());

        assert!(registry.get(2).is_some());
        assert!(registry.get(3).is_some());
        assert!(registry.get(4).is_none());

        registry.mark_healthy(2, false);
        assert!(!registry.get(2).unwrap().is_healthy);

        let healthy = registry.all_healthy();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].node_id, 3);
    }

    #[test]
    fn server_rejects_oversized_payload() {
        let handler = Arc::new(CountingHandler::default());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(NodeRegistry::new(1));
        registry.register(2, addr, test_auth_config());

        let server = {
            let handler = Arc::clone(&handler);
            let registry = Arc::clone(&registry);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                TcpServer::handle_connection(1, registry, stream, handler);
            })
        };

        let mut client = TcpStream::connect(addr).unwrap();
        perform_test_handshake(&mut client, 2, 1);
        let header =
            MessageHeader::new(MessageType::WriteBlock, 2, 1, (MAX_MESSAGE_SIZE as u32) + 1);
        client.write_all(&header.to_bytes()).unwrap();
        client.flush().unwrap();

        drop(client);
        server.join().unwrap();

        assert_eq!(handler.write_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn server_rejects_zero_length_payload_for_write() {
        let handler = Arc::new(CountingHandler::default());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(NodeRegistry::new(10));
        registry.register(20, addr, test_auth_config());

        let server = {
            let handler = Arc::clone(&handler);
            let registry = Arc::clone(&registry);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                TcpServer::handle_connection(10, registry, stream, handler);
            })
        };

        let mut client = TcpStream::connect(addr).unwrap();
        perform_test_handshake(&mut client, 20, 10);
        let header = MessageHeader::new(MessageType::WriteBlock, 20, 10, 0);
        client.write_all(&header.to_bytes()).unwrap();
        client.flush().unwrap();

        let mut resp_header_buf = [0u8; MessageHeader::SIZE];
        client.read_exact(&mut resp_header_buf).unwrap();
        let resp_header = MessageHeader::from_bytes(&resp_header_buf);

        drop(client);
        server.join().unwrap();

        let resp_msg_type = resp_header.msg_type;
        assert_eq!(resp_msg_type, MessageType::Error as u16);
        assert_eq!(handler.write_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn client_rejects_oversized_response_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let header =
                MessageHeader::new(MessageType::ReadReply, 1, 2, (MAX_MESSAGE_SIZE as u32) + 1);
            stream.write_all(&header.to_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let transport = TcpTransport::new(2);
        let mut client_stream = TcpStream::connect(addr).unwrap();
        let result = transport.recv_response(&mut client_stream, 1);

        server.join().unwrap();
        assert!(matches!(result, Err(IoError::Corrupted)));
    }

    #[test]
    fn unauthorized_connection_fails_before_ops() {
        let handler = Arc::new(CountingHandler::default());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_registry = Arc::new(NodeRegistry::new(1));
        server_registry.register(2, addr, test_auth_config());

        let server = {
            let handler = Arc::clone(&handler);
            let registry = Arc::clone(&server_registry);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                TcpServer::handle_connection(1, registry, stream, handler);
            })
        };

        let transport = TcpTransport::new(2);
        // Register server with wrong secret so handshake fails
        transport.registry().register(
            1,
            addr,
            NodeAuthConfig::new(SharedSecret::new(
                TEST_KEY_ID,
                b"wrong-shared-secret".to_vec(),
            )),
        );

        let mut buf = [0u8; BLOCK_SIZE];
        let result = transport.read_remote(1, BlockAddr::new(1, 0, 0, 0), &mut buf);

        server.join().unwrap();
        assert!(matches!(result, Err(IoError::PermissionDenied)));
        assert_eq!(handler.read_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mismatched_node_id_header_is_rejected() {
        let handler = Arc::new(CountingHandler::default());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(NodeRegistry::new(10));
        registry.register(20, addr, test_auth_config());

        let server = {
            let handler = Arc::clone(&handler);
            let registry = Arc::clone(&registry);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                TcpServer::handle_connection(10, registry, stream, handler);
            })
        };

        let mut client = TcpStream::connect(addr).unwrap();
        perform_test_handshake(&mut client, 20, 10);

        // Craft header claiming a different source_node (30) after authenticating as 20.
        let header = MessageHeader::new(MessageType::Ping, 30, 10, 0);
        client.write_all(&header.to_bytes()).unwrap();
        client.flush().unwrap();

        // Server should close the connection without invoking handler.
        let mut resp_buf = [0u8; MessageHeader::SIZE];
        let _ = client.read_exact(&mut resp_buf); // May error if closed early.

        drop(client);
        server.join().unwrap();

        assert_eq!(handler.read_calls.load(Ordering::SeqCst), 0);
        assert_eq!(handler.write_calls.load(Ordering::SeqCst), 0);
    }
}
