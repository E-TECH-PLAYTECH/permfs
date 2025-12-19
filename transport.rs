// PermFS Network Transport — TCP-based cluster communication

#![cfg(feature = "network")]

use crate::sync::{Arc, Mutex, RwLock};
use crate::{AllocError, BlockAddr, ClusterTransport, FsResult, IoError, BLOCK_SIZE};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
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
}

pub struct NodeRegistry {
    nodes: RwLock<HashMap<u64, NodeInfo>>,
    local_node_id: u64,
}

impl NodeRegistry {
    pub fn new(local_node_id: u64) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            local_node_id,
        }
    }

    pub fn register(&self, node_id: u64, address: SocketAddr) {
        let mut nodes = self.nodes.write();
        nodes.insert(
            node_id,
            NodeInfo {
                node_id,
                address,
                last_seen: 0,
                is_healthy: true,
            },
        );
    }

    pub fn unregister(&self, node_id: u64) {
        let mut nodes = self.nodes.write();
        nodes.remove(&node_id);
    }

    pub fn get(&self, node_id: u64) -> Option<NodeInfo> {
        let nodes = self.nodes.read();
        nodes.get(&node_id).cloned()
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
                    // Try to clone the stream (this checks if it's still valid)
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

        // Create new connection
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|_| IoError::IoFailed)?;

        socket.set_nodelay(true).ok();
        socket.set_keepalive(true).ok();

        let sock_addr = SockAddr::from(info.address);
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

    fn recv_response(&self, stream: &mut TcpStream) -> Result<(MessageHeader, Vec<u8>), IoError> {
        let mut header_buf = [0u8; MessageHeader::SIZE];
        stream
            .read_exact(&mut header_buf)
            .map_err(|_| IoError::NetworkTimeout)?;

        let header = MessageHeader::from_bytes(&header_buf);
        if !header.is_valid() {
            return Err(IoError::Corrupted);
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
            let (resp_header, payload) = this.recv_response(&mut stream)?;

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
            let (resp_header, _) = this.recv_response(&mut stream)?;

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
                .recv_response(&mut stream)
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
                .recv_response(&mut stream)
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
}

impl TcpServer {
    pub fn bind(local_node_id: u64, addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;

        Ok(Self {
            local_node_id,
            listener,
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    pub fn run<H: RequestHandler + 'static>(&self, handler: Arc<H>) {
        while self.running.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let handler = Arc::clone(&handler);
                    let node_id = self.local_node_id;
                    std::thread::spawn(move || {
                        Self::handle_connection(node_id, stream, handler);
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
        mut stream: TcpStream,
        handler: Arc<H>,
    ) {
        stream
            .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)))
            .ok();

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
                if stream
                    .read_exact(&mut payload_buf[..payload_len])
                    .is_err()
                {
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

        registry.register(2, "127.0.0.1:7432".parse().unwrap());
        registry.register(3, "127.0.0.1:7433".parse().unwrap());

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

        let server = {
            let handler = Arc::clone(&handler);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                TcpServer::handle_connection(1, stream, handler);
            })
        };

        let mut client = TcpStream::connect(addr).unwrap();
        let header = MessageHeader::new(
            MessageType::WriteBlock,
            2,
            1,
            (MAX_MESSAGE_SIZE as u32) + 1,
        );
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

        let server = {
            let handler = Arc::clone(&handler);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                TcpServer::handle_connection(10, stream, handler);
            })
        };

        let mut client = TcpStream::connect(addr).unwrap();
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
            let header = MessageHeader::new(
                MessageType::ReadReply,
                1,
                2,
                (MAX_MESSAGE_SIZE as u32) + 1,
            );
            stream.write_all(&header.to_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let transport = TcpTransport::new(2);
        let mut client_stream = TcpStream::connect(addr).unwrap();
        let result = transport.recv_response(&mut client_stream);

        server.join().unwrap();
        assert!(matches!(result, Err(IoError::Corrupted)));
    }
}
