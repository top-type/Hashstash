//! Optional pinned, authenticated peer transport. This is node policy, not consensus.
//! Frames are signed, not encrypted. Never use a spending key as a peer identity.
use crate::{
    crypto,
    network_guard::{Busy, Session},
    types::{Hash, PublicKey},
};
use anyhow::{Context, Result, ensure};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
    str::FromStr,
    sync::{Arc, OnceLock},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Semaphore,
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"HSP2PAUT";
const HANDSHAKE_TAG: &str = "Hashstash/PeerHandshake";
const SESSION_TAG: &str = "Hashstash/PeerSession";
const FRAME_TAG: &str = "Hashstash/PeerFrame";
const KEY_FORMAT: &str = "hashstash-peer-v1";
const FRAME_HEADER: usize = 4 + 8 + 64;
/// Wait for a shared verification worker, as for other peer workers.
const VERIFY_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct PeerPin {
    pub address: SocketAddr,
    pub public_key: PublicKey,
}
impl FromStr for PeerPin {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let (address, key) = value
            .split_once('=')
            .context("peer pin requires IP:PORT=PUBLIC_KEY")?;
        let address: SocketAddr = address
            .parse()
            .context("peer pin requires a numeric IP:PORT")?;
        ensure!(
            address.port() != 0 && !address.ip().is_unspecified(),
            "peer pin requires a reachable address"
        );
        let public_key: PublicKey = hex::decode(key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("peer public key requires 32 bytes"))?;
        ensure!(crypto::valid_key(&public_key), "invalid peer public key");
        Ok(Self {
            address,
            public_key,
        })
    }
}

struct Identity {
    secret: Zeroizing<[u8; 32]>,
    public: PublicKey,
}
impl Identity {
    fn new(secret: [u8; 32]) -> Result<Self> {
        let secret = Zeroizing::new(secret);
        Ok(Self {
            public: crypto::public_key(&secret)?,
            secret,
        })
    }
    fn sign(&self, message: Hash) -> Result<[u8; 64]> {
        // Every frame is signed: reuse one context and erase the expanded
        // secret copies after each signature.
        let context = signing_context();
        let mut secret = SecretKey::from_byte_array(*self.secret)?;
        let mut pair = Keypair::from_secret_key(context, &secret);
        secret.non_secure_erase();
        let mut aux = Zeroizing::new([0u8; 32]);
        let signature = getrandom::fill(aux.as_mut())
            .map_err(|e| anyhow::anyhow!("peer randomness unavailable: {e}"))
            .map(|()| *context.sign_schnorr_with_aux_rand(&message, &pair, &aux).as_ref());
        pair.non_secure_erase();
        signature
    }
}
fn signing_context() -> &'static Secp256k1<secp256k1::All> {
    static CONTEXT: OnceLock<Secp256k1<secp256k1::All>> = OnceLock::new();
    CONTEXT.get_or_init(Secp256k1::new)
}
fn verification_context() -> &'static Secp256k1<secp256k1::VerifyOnly> {
    static CONTEXT: OnceLock<Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();
    CONTEXT.get_or_init(Secp256k1::verification_only)
}
fn verify(key: PublicKey, digest: Hash, signature: [u8; 64]) -> Result<()> {
    verification_context()
        .verify_schnorr(
            &Signature::from_byte_array(signature),
            &digest,
            &XOnlyPublicKey::from_byte_array(key)?,
        )
        .context("peer authentication failed")
}
fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn normalized_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v) if v.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(normalized(address.ip()), address.port())
        }
        _ => address,
    }
}

pub struct Policy {
    identity: Arc<Identity>,
    pins: BTreeMap<SocketAddr, PublicKey>,
    discovery: bool,
}
impl Policy {
    pub fn new(secret: [u8; 32], pins: Vec<PeerPin>) -> Result<Arc<Self>> {
        Self::build(secret, pins, false)
    }
    /// Public participation proves possession of a transport key without an
    /// operator allowlist. Explicit pins still constrain their destinations.
    pub fn discovery(secret: [u8; 32], pins: Vec<PeerPin>) -> Result<Arc<Self>> {
        Self::build(secret, pins, true)
    }
    fn build(secret: [u8; 32], pins: Vec<PeerPin>, discovery: bool) -> Result<Arc<Self>> {
        let identity = Arc::new(Identity::new(secret)?);
        ensure!(
            (discovery || !pins.is_empty()) && pins.len() <= 64,
            "closed authenticated peers require 1 to 64 pins; discovery permits 0 to 64"
        );
        let mut map = BTreeMap::new();
        for pin in pins {
            ensure!(
                crypto::valid_key(&pin.public_key) && pin.public_key != identity.public,
                "invalid or self peer pin"
            );
            ensure!(
                map.insert(normalized_address(pin.address), pin.public_key)
                    .is_none(),
                "duplicate peer pin address"
            );
        }
        Ok(Arc::new(Self {
            identity,
            pins: map,
            discovery,
        }))
    }
    pub fn is_discovery(&self) -> bool {
        self.discovery
    }
    pub fn public_key(&self) -> PublicKey {
        self.identity.public
    }
    pub fn validate_peers(&self, peers: &[SocketAddr]) -> Result<()> {
        ensure!(
            self.discovery
                || (peers.len() == self.pins.len()
                    && peers
                        .iter()
                        .all(|p| self.pins.contains_key(&normalized_address(*p)))),
            "every configured peer must have exactly one pin; no unpinned fallback"
        );
        let unique: std::collections::BTreeSet<_> =
            peers.iter().map(|p| normalized_address(*p)).collect();
        ensure!(unique.len() == peers.len(), "duplicate configured peer");
        Ok(())
    }
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.discovery
            || self
                .pins
                .keys()
                .any(|p| normalized(p.ip()) == normalized(ip))
    }
    /// Addresses of explicitly pinned peers.
    pub fn pinned_ips(&self) -> Vec<IpAddr> {
        self.pins.keys().map(|p| normalized(p.ip())).collect()
    }
    /// An outgoing endpoint pinned exactly requires that key. In discovery
    /// mode, another port on a pinned IP must prove one of that IP's keys,
    /// matching the incoming per-IP rule; other endpoints accept any key.
    fn outgoing_keys(&self, peer: SocketAddr) -> Result<Vec<PublicKey>> {
        if let Some(key) = self.pins.get(&normalized_address(peer)) {
            return Ok(vec![*key]);
        }
        ensure!(self.discovery, "unpinned outgoing peer");
        Ok(self
            .pins
            .iter()
            .filter(|(p, _)| normalized(p.ip()) == normalized(peer.ip()))
            .map(|(_, key)| *key)
            .collect())
    }
    fn allows(&self, ip: IpAddr, key: PublicKey) -> bool {
        if key == self.identity.public || !crypto::valid_key(&key) {
            return false;
        }
        let mut source_pins = self
            .pins
            .iter()
            .filter(|(p, _)| normalized(p.ip()) == normalized(ip))
            .peekable();
        if source_pins.peek().is_some() {
            source_pins.any(|(_, pinned)| *pinned == key)
        } else {
            self.discovery
        }
    }
    pub fn from_file(path: &Path, pins: Vec<PeerPin>) -> Result<Arc<Self>> {
        Self::new(read_key(path)?, pins)
    }
    pub fn discovery_from_file(path: &Path, pins: Vec<PeerPin>) -> Result<Arc<Self>> {
        Self::discovery(read_key(path)?, pins)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    secret: String,
    public: String,
}
impl Drop for KeyFile {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
fn read_key(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 512,
        "invalid peer key file"
    );
    // Read through one handle, and require that handle to be the regular file
    // inspected above: a path swapped for a symbolic link in between fails.
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT opens a symbolic link or junction
        // itself rather than its target, so the checks below reject it.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    ensure!(
        opened.is_file() && !opened.file_type().is_symlink() && opened.len() <= 512,
        "invalid peer key file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            opened.dev() == metadata.dev() && opened.ino() == metadata.ino(),
            "peer key file changed while it was opened"
        );
        ensure!(
            opened.permissions().mode() & 0o077 == 0,
            "peer key file must be owner-only (0600)"
        );
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(513).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 512, "peer key file too large");
    let key: KeyFile = serde_json::from_slice(&bytes).context("invalid peer identity file")?;
    ensure!(
        key.format == KEY_FORMAT,
        "dedicated peer identity file required; spending keys are not accepted"
    );
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(&key.secret, secret.as_mut()).context("invalid peer identity")?;
    ensure!(
        hex::encode(crypto::public_key(&secret)?) == key.public,
        "peer identity public key mismatch"
    );
    Ok(*secret)
}
/// Creates a new owner-only identity file and returns only its public key.
pub fn generate_key_file(path: &Path) -> Result<PublicKey> {
    let identity = loop {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut())
            .map_err(|e| anyhow::anyhow!("peer randomness unavailable: {e}"))?;
        if let Ok(identity) = Identity::new(*secret) {
            break identity;
        }
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("create peer identity (existing files are never overwritten)")?;
    // Owner-only before the secret is written, on Windows too.
    crate::local_files::restrict_to_owner(path)?;
    let key = KeyFile {
        format: KEY_FORMAT.to_owned(),
        secret: hex::encode(*identity.secret),
        public: hex::encode(identity.public),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&key)?);
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(identity.public)
}

fn transcript(
    chain: Hash,
    client: PublicKey,
    server: PublicKey,
    client_nonce: Hash,
    server_nonce: Hash,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(168);
    for part in [
        MAGIC.as_slice(),
        &chain,
        &client,
        &server,
        &client_nonce,
        &server_nonce,
    ] {
        bytes.extend_from_slice(part);
    }
    bytes
}
fn proof(transcript: &[u8], role: u8) -> Hash {
    let mut bytes = transcript.to_vec();
    bytes.push(role);
    crypto::tagged_hash(HANDSHAKE_TAG, &bytes)
}
fn random_nonce() -> Result<Hash> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("peer randomness unavailable: {e}"))?;
    Ok(nonce)
}

pub struct Channel {
    identity: Arc<Identity>,
    remote: PublicKey,
    session: Hash,
    send_role: u8,
    send: u64,
    receive: u64,
}
impl Channel {
    pub fn remote_key(&self) -> PublicKey {
        self.remote
    }
    fn new(identity: Arc<Identity>, remote: PublicKey, transcript: &[u8], client: bool) -> Self {
        Self {
            identity,
            remote,
            session: crypto::tagged_hash(SESSION_TAG, transcript),
            send_role: u8::from(!client),
            send: 0,
            receive: 0,
        }
    }
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        policy: &Policy,
        peer: SocketAddr,
        chain: Hash,
        admission: &Session,
    ) -> Result<Self> {
        let expected = policy.outgoing_keys(peer)?;
        let nonce = random_nonce()?;
        let mut hello = Vec::with_capacity(104);
        hello.extend_from_slice(MAGIC);
        hello.extend_from_slice(&chain);
        hello.extend_from_slice(&policy.identity.public);
        hello.extend_from_slice(&nonce);
        admission.bytes(hello.len())?;
        stream.write_all(&hello).await?;
        let mut reply = [0u8; 136];
        stream.read_exact(&mut reply).await?;
        admission.bytes(reply.len())?;
        let server: PublicKey = reply[8..40].try_into()?;
        ensure!(
            &reply[..8] == MAGIC
                && crypto::valid_key(&server)
                && server != policy.identity.public
                && (expected.is_empty() || expected.contains(&server)),
            "pinned peer identity mismatch"
        );
        let transcript = transcript(
            chain,
            policy.identity.public,
            server,
            nonce,
            reply[40..72].try_into()?,
        );
        admission.work(2)?;
        verify(server, proof(&transcript, 1), reply[72..].try_into()?)?;
        let signature = policy.identity.sign(proof(&transcript, 0))?;
        admission.bytes(signature.len())?;
        stream.write_all(&signature).await?;
        Ok(Self::new(
            policy.identity.clone(),
            server,
            &transcript,
            true,
        ))
    }
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        policy: &Policy,
        ip: IpAddr,
        chain: Hash,
        admission: &Session,
    ) -> Result<Self> {
        ensure!(policy.allows_ip(ip), "unconfigured peer source");
        let mut hello = [0u8; 104];
        stream.read_exact(&mut hello).await?;
        admission.bytes(hello.len())?;
        ensure!(
            &hello[..8] == MAGIC && hello[8..40] == chain,
            "peer authentication format or chain mismatch"
        );
        let client = hello[40..72].try_into()?;
        ensure!(policy.allows(ip, client), "unpinned incoming peer identity");
        let nonce = random_nonce()?;
        let transcript = transcript(
            chain,
            client,
            policy.identity.public,
            hello[72..104].try_into()?,
            nonce,
        );
        admission.work(2)?;
        let mut reply = Vec::with_capacity(136);
        reply.extend_from_slice(MAGIC);
        reply.extend_from_slice(&policy.identity.public);
        reply.extend_from_slice(&nonce);
        reply.extend_from_slice(&policy.identity.sign(proof(&transcript, 1))?);
        admission.bytes(reply.len())?;
        stream.write_all(&reply).await?;
        let mut signature = [0u8; 64];
        stream.read_exact(&mut signature).await?;
        admission.bytes(signature.len())?;
        verify(client, proof(&transcript, 0), signature)?;
        Ok(Self::new(
            policy.identity.clone(),
            client,
            &transcript,
            false,
        ))
    }
    fn frame_digest(session: Hash, role: u8, sequence: u64, bytes: &[u8]) -> Hash {
        let mut commitment = Vec::with_capacity(77);
        commitment.extend_from_slice(&session);
        commitment.push(role);
        commitment.extend_from_slice(&sequence.to_be_bytes());
        commitment.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        commitment.extend_from_slice(&crypto::sha256d(bytes));
        crypto::tagged_hash(FRAME_TAG, &commitment)
    }
    /// Called inside the bounded peer serialization worker.
    pub fn seal(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let length = u32::try_from(bytes.len())?;
        let signature = self.identity.sign(Self::frame_digest(
            self.session,
            self.send_role,
            self.send,
            &bytes,
        ))?;
        let mut frame = Vec::with_capacity(FRAME_HEADER + bytes.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&self.send.to_be_bytes());
        frame.extend_from_slice(&signature);
        frame.extend_from_slice(&bytes);
        self.send = self
            .send
            .checked_add(1)
            .context("peer send sequence exhausted")?;
        Ok(frame)
    }
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        read: &mut R,
        max: usize,
        admission: &Session,
        workers: Arc<Semaphore>,
    ) -> Result<Vec<u8>> {
        let frame = self.receive(read, max, admission).await?;
        self.open(frame, admission, workers).await
    }
    /// Read one signed frame. Only the peer's input is awaited, so a
    /// deadline on this step measures the peer alone.
    pub async fn receive<R: AsyncRead + Unpin>(
        &self,
        read: &mut R,
        max: usize,
        admission: &Session,
    ) -> Result<SealedFrame> {
        let mut header = [0u8; FRAME_HEADER];
        read.read_exact(&mut header).await?;
        admission.bytes(header.len())?;
        admission.begin_frame()?;
        let length = u32::from_be_bytes(header[..4].try_into()?) as usize;
        ensure!(
            length > 0 && length <= max,
            "authenticated peer frame too large or empty"
        );
        let sequence = u64::from_be_bytes(header[4..12].try_into()?);
        ensure!(
            sequence == self.receive,
            "peer frame replay or sequence mismatch"
        );
        let signature = header[12..].try_into()?;
        let mut bytes = Vec::with_capacity(length.min(8192));
        let mut chunk = [0u8; 8192];
        while bytes.len() < length {
            let take = chunk.len().min(length - bytes.len());
            admission.reserve_frame(take)?;
            read.read_exact(&mut chunk[..take]).await?;
            admission.bytes(take)?;
            bytes.extend_from_slice(&chunk[..take]);
        }
        Ok(SealedFrame {
            sequence,
            signature,
            bytes,
        })
    }
    /// Verify a received frame on a bounded worker. Waiting for a worker is
    /// local capacity and fails as `Busy`; a bad signature is the peer's.
    pub async fn open(
        &mut self,
        frame: SealedFrame,
        admission: &Session,
        workers: Arc<Semaphore>,
    ) -> Result<Vec<u8>> {
        ensure!(
            frame.sequence == self.receive,
            "peer frame replay or sequence mismatch"
        );
        admission.work(1)?;
        let permit = tokio::time::timeout(VERIFY_WAIT, workers.acquire_owned())
            .await
            .map_err(|_| Busy("peer authentication workers busy"))??;
        let (session, role, key) = (self.session, 1 - self.send_role, self.remote);
        let SealedFrame {
            sequence,
            signature,
            bytes,
        } = frame;
        let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let _permit = permit;
            verify(
                key,
                Self::frame_digest(session, role, sequence, &bytes),
                signature,
            )?;
            Ok(bytes)
        })
        .await
        .context("peer authentication worker failed")??;
        self.receive = self
            .receive
            .checked_add(1)
            .context("peer receive sequence exhausted")?;
        Ok(bytes)
    }
}
/// A signed frame that has been read but not yet verified.
pub struct SealedFrame {
    sequence: u64,
    signature: [u8; 64],
    bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_guard::{NetworkGuard, Surface};
    use tokio::time::{Duration, timeout};

    fn fixture(secret: u8, remote: u8, port: u16) -> Arc<Policy> {
        Policy::new(
            [secret; 32],
            vec![PeerPin {
                address: SocketAddr::from(([127, 0, 0, 1], port)),
                public_key: crypto::public_key(&[remote; 32]).unwrap(),
            }],
        )
        .unwrap()
    }
    fn admission() -> Session {
        Arc::new(NetworkGuard::default())
            .admit(IpAddr::from([127, 0, 0, 1]), Surface::Peer)
            .unwrap()
    }
    async fn handshake_policies(
        a: Arc<Policy>,
        b: Arc<Policy>,
        client_chain: Hash,
        server_chain: Hash,
    ) -> (Result<Channel>, Result<Channel>) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let left = async move {
            Channel::connect(
                &mut client,
                &a,
                "127.0.0.1:1002".parse().unwrap(),
                client_chain,
                &admission(),
            )
            .await
        };
        let right = async move {
            Channel::accept(
                &mut server,
                &b,
                "127.0.0.1".parse().unwrap(),
                server_chain,
                &admission(),
            )
            .await
        };
        timeout(Duration::from_secs(2), async { tokio::join!(left, right) })
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn discovery_authenticates_new_participants_and_signed_frames() {
        let a = Policy::discovery([81; 32], vec![]).unwrap();
        let b = Policy::discovery([82; 32], vec![]).unwrap();
        let ak = a.public_key();
        let bk = b.public_key();
        let (a, b) = handshake_policies(a, b, [9; 32], [9; 32]).await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.remote_key(), bk);
        assert_eq!(b.remote_key(), ak);
        assert_eq!(a.session, b.session);
        let frame = a.seal(b"new participant block".to_vec()).unwrap();
        assert_eq!(
            receive(&mut b, frame.clone(), 1024).await.unwrap(),
            b"new participant block"
        );
        assert!(receive(&mut b, frame, 1024).await.is_err());
        let reply = b.seal(b"verified peer response".to_vec()).unwrap();
        assert_eq!(
            receive(&mut a, reply, 1024).await.unwrap(),
            b"verified peer response"
        );
    }
    #[tokio::test]
    async fn discovery_keeps_configured_outgoing_and_incoming_pins_mandatory() {
        // An open client must not accept a different key at a pinned endpoint.
        let a = Policy::discovery(
            [81; 32],
            vec![PeerPin {
                address: "127.0.0.1:1002".parse().unwrap(),
                public_key: crypto::public_key(&[83; 32]).unwrap(),
            }],
        )
        .unwrap();
        let b = Policy::discovery([82; 32], vec![]).unwrap();
        let (a, b) = handshake_policies(a, b, [9; 32], [9; 32]).await;
        assert!(a.is_err() && b.is_err());
        // Known incoming source addresses also retain their configured key pins.
        let a = Policy::discovery([81; 32], vec![]).unwrap();
        let b = Policy::discovery(
            [82; 32],
            vec![PeerPin {
                address: "127.0.0.1:1001".parse().unwrap(),
                public_key: crypto::public_key(&[83; 32]).unwrap(),
            }],
        )
        .unwrap();
        let (a, b) = handshake_policies(a, b, [9; 32], [9; 32]).await;
        assert!(a.is_err() && b.is_err());
    }
    #[tokio::test]
    async fn outgoing_pins_cover_every_port_on_a_pinned_ip() {
        let pinned = crypto::public_key(&[83; 32]).unwrap();
        let client = Policy::discovery(
            [81; 32],
            vec![PeerPin {
                address: "127.0.0.1:1002".parse().unwrap(),
                public_key: pinned,
            }],
        )
        .unwrap();
        assert_eq!(
            client
                .outgoing_keys("127.0.0.1:1003".parse().unwrap())
                .unwrap(),
            vec![pinned]
        );
        assert!(
            client
                .outgoing_keys("127.0.0.2:1003".parse().unwrap())
                .unwrap()
                .is_empty()
        );
        for (secret, accepted) in [(82, false), (83, true)] {
            let server = Policy::discovery([secret; 32], vec![]).unwrap();
            let (mut a, mut b) = tokio::io::duplex(4096);
            let client = client.clone();
            // Each side owns its stream, so a rejected handshake closes it.
            let left = async move {
                Channel::connect(
                    &mut a,
                    &client,
                    "127.0.0.1:1003".parse().unwrap(),
                    [9; 32],
                    &admission(),
                )
                .await
            };
            let right = async move {
                Channel::accept(
                    &mut b,
                    &server,
                    "127.0.0.1".parse().unwrap(),
                    [9; 32],
                    &admission(),
                )
                .await
            };
            let (left, right) = timeout(Duration::from_secs(2), async { tokio::join!(left, right) })
                .await
                .unwrap();
            assert_eq!(left.is_ok(), accepted);
            assert_eq!(right.is_ok(), accepted);
        }
        let closed = fixture(81, 82, 1002);
        assert!(
            closed
                .outgoing_keys("127.0.0.1:1003".parse().unwrap())
                .is_err()
        );
    }
    #[tokio::test]
    async fn discovery_rejects_wrong_chain_and_self_connections() {
        for (server_secret, chain) in [(82, [8; 32]), (81, [9; 32])] {
            let a = Policy::discovery([81; 32], vec![]).unwrap();
            let b = Policy::discovery([server_secret; 32], vec![]).unwrap();
            let (a, b) = handshake_policies(a, b, [9; 32], chain).await;
            assert!(a.is_err() && b.is_err());
        }
    }
    #[test]
    fn discovery_is_explicit_and_preserves_pin_validation() {
        assert!(Policy::new([81; 32], vec![]).is_err());
        let open = Policy::discovery([81; 32], vec![]).unwrap();
        assert!(open.is_discovery());
        assert!(open.allows_ip("203.0.113.1".parse().unwrap()));
        open.validate_peers(&[]).unwrap();
        let address = "203.0.113.1:18481".parse().unwrap();
        open.validate_peers(&[address]).unwrap();
        assert!(open.validate_peers(&[address, address]).is_err());
        assert!(!fixture(81, 82, 1002).is_discovery());
        assert!(
            Policy::discovery(
                [81; 32],
                vec![PeerPin {
                    address,
                    public_key: open.public_key(),
                }]
            )
            .is_err()
        );
        assert!(
            Policy::discovery(
                [81; 32],
                vec![PeerPin {
                    address,
                    public_key: [255; 32],
                }]
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn discovery_does_not_accept_unsigned_legacy_traffic() {
        let open = Policy::discovery([82; 32], vec![]).unwrap();
        let (mut write, mut read) = tokio::io::duplex(4096);
        write.write_all(&[b'{'; 104]).await.unwrap();
        assert!(
            Channel::accept(
                &mut read,
                &open,
                "127.0.0.1".parse().unwrap(),
                [9; 32],
                &admission()
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn mapped_addresses_cannot_bypass_pins_or_duplicate_checks() {
        let address = "127.0.0.1:1002".parse().unwrap();
        let mapped = "[::ffff:127.0.0.1]:1002".parse().unwrap();
        let pin = PeerPin {
            address: mapped,
            public_key: crypto::public_key(&[83; 32]).unwrap(),
        };
        let a = Policy::discovery([81; 32], vec![pin.clone()]).unwrap();
        let b = Policy::discovery([82; 32], vec![]).unwrap();
        let (a, b) = handshake_policies(a, b, [9; 32], [9; 32]).await;
        assert!(a.is_err() && b.is_err());
        let closed = Policy::new([81; 32], vec![pin.clone()]).unwrap();
        closed.validate_peers(&[address]).unwrap();
        assert!(closed.validate_peers(&[address, mapped]).is_err());
        let same_pin = PeerPin {
            address,
            public_key: pin.public_key,
        };
        assert!(Policy::discovery([81; 32], vec![pin, same_pin]).is_err());
    }
    async fn pair() -> (Channel, Channel) {
        let a = fixture(81, 82, 1002);
        let b = fixture(82, 81, 1001);
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ca = admission();
        let sa = admission();
        let (client, server) = tokio::join!(
            Channel::connect(
                &mut client,
                &a,
                "127.0.0.1:1002".parse().unwrap(),
                [9; 32],
                &ca
            ),
            Channel::accept(&mut server, &b, "127.0.0.1".parse().unwrap(), [9; 32], &sa)
        );
        (client.unwrap(), server.unwrap())
    }
    async fn receive(channel: &mut Channel, wire: Vec<u8>, limit: usize) -> Result<Vec<u8>> {
        let (mut write, mut read) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let _ = write.write_all(&wire).await;
        });
        let result = timeout(
            Duration::from_secs(2),
            channel.read(&mut read, limit, &admission(), Arc::new(Semaphore::new(2))),
        )
        .await?;
        drop(read);
        writer.await?;
        result
    }
    #[tokio::test]
    async fn mutual_pin_handshake_and_bidirectional_frames() {
        let (mut a, mut b) = pair().await;
        assert_eq!(a.session, b.session);
        let wire = a.seal(b"client block batch".to_vec()).unwrap();
        assert_eq!(
            receive(&mut b, wire, 1024).await.unwrap(),
            b"client block batch"
        );
        let wire = b.seal(b"server reply".to_vec()).unwrap();
        assert_eq!(receive(&mut a, wire, 1024).await.unwrap(), b"server reply");
    }
    #[tokio::test]
    async fn replay_tampering_reflection_and_cross_session_are_rejected() {
        let (mut a, mut b) = pair().await;
        let original = a.seal(b"a signed payload".to_vec()).unwrap();
        receive(&mut b, original.clone(), 1024).await.unwrap();
        assert!(receive(&mut b, original.clone(), 1024).await.is_err());
        let (_, mut other) = pair().await;
        assert!(receive(&mut other, original, 1024).await.is_err());
        let (mut a, mut b) = pair().await;
        let mut tampered = a.seal(b"block body".to_vec()).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(receive(&mut b, tampered, 1024).await.is_err());
        let (mut a, _) = pair().await;
        let reflected = a.seal(b"reflection".to_vec()).unwrap();
        assert!(receive(&mut a, reflected, 1024).await.is_err());
    }
    #[tokio::test]
    async fn length_and_sequence_are_rejected_before_reading_an_unbounded_body() {
        let (mut a, mut b) = pair().await;
        let mut frame = a.seal(b"small".to_vec()).unwrap();
        frame[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        frame.truncate(FRAME_HEADER);
        assert!(
            receive(&mut b, frame, 1024)
                .await
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
        let mut frame = a.seal(b"small".to_vec()).unwrap();
        frame[4..12].copy_from_slice(&9u64.to_be_bytes());
        frame.truncate(FRAME_HEADER);
        assert!(
            receive(&mut b, frame, 1024)
                .await
                .unwrap_err()
                .to_string()
                .contains("sequence")
        );
    }
    #[tokio::test]
    async fn wrong_identity_wrong_chain_and_legacy_hello_fail_closed() {
        for (remote, chain) in [(83, [9; 32]), (82, [8; 32])] {
            let a = fixture(81, remote, 1002);
            let b = fixture(82, 81, 1001);
            let (mut client, mut server) = tokio::io::duplex(4096);
            let left = async move {
                Channel::connect(
                    &mut client,
                    &a,
                    "127.0.0.1:1002".parse().unwrap(),
                    chain,
                    &admission(),
                )
                .await
            };
            let right = async move {
                Channel::accept(
                    &mut server,
                    &b,
                    "127.0.0.1".parse().unwrap(),
                    [9; 32],
                    &admission(),
                )
                .await
            };
            let (left, right) =
                timeout(Duration::from_secs(2), async { tokio::join!(left, right) })
                    .await
                    .unwrap();
            assert!(left.is_err() && right.is_err());
        }
        let b = fixture(82, 81, 1001);
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&[b'{'; 104]).await.unwrap();
        assert!(
            Channel::accept(
                &mut server,
                &b,
                "127.0.0.1".parse().unwrap(),
                [9; 32],
                &admission()
            )
            .await
            .is_err()
        );
    }
    #[test]
    fn handshake_proof_binds_both_roles_keys_chain_and_fresh_challenges() {
        let id = Identity::new([81; 32]).unwrap();
        let server = crypto::public_key(&[82; 32]).unwrap();
        let t = transcript([1; 32], id.public, server, [2; 32], [3; 32]);
        let signature = id.sign(proof(&t, 0)).unwrap();
        verify(id.public, proof(&t, 0), signature).unwrap();
        assert!(verify(id.public, proof(&t, 1), signature).is_err());
        for offset in [8, 40, 72, 104, 136] {
            let mut changed = t.clone();
            changed[offset] ^= 1;
            assert!(verify(id.public, proof(&changed, 0), signature).is_err());
        }
    }
    #[test]
    fn dedicated_key_file_and_complete_pin_configuration_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer.json");
        let public = generate_key_file(&path).unwrap();
        assert_eq!(
            crypto::public_key(&read_key(&path).unwrap()).unwrap(),
            public
        );
        assert!(generate_key_file(&path).is_err());
        let wallet = dir.path().join("wallet.json");
        fs::write(&wallet, b"{\"secret\":\"never accept a wallet here\"}").unwrap();
        assert!(read_key(&wallet).is_err());
        let policy = fixture(81, 82, 1002);
        assert!(policy.validate_peers(&[]).is_err());
        assert!(
            policy
                .validate_peers(&["127.0.0.1:1003".parse().unwrap()])
                .is_err()
        );
        policy
            .validate_peers(&["127.0.0.1:1002".parse().unwrap()])
            .unwrap();
        assert!(!policy.allows_ip("192.0.2.1".parse().unwrap()));
        assert!(!policy.allows(
            "127.0.0.1".parse().unwrap(),
            crypto::public_key(&[83; 32]).unwrap()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_key(&path).is_err());
        }
    }
}
