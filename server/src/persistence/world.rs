//! World state on the Internet Computer (Phase 4, `VELOREN_PERSISTENCE=ic`).
//!
//! The world's durable state lives in the realm canister as two blobs: rtsim
//! data and the `server_config/` files. Local files are only a working copy;
//! the IC is the source of truth:
//! * start-up: `restore_server_config` writes the config files before settings
//!   load; rtsim loads its data from the IC (see `rtsim/mod.rs`).
//! * running: rtsim's save thread uploads every `VELOREN_REALM_SYNC_SECS`
//!   (default 600) and on shutdown; config files are uploaded when they change.
//!
//! Blobs are deflate-compressed here (rtsim msgpack compresses ~39×: 5 MB → 131 KB),
//! which is what keeps the cycle cost low; see docs/cost-log.md in veloren-ic.

use super::{character::ic::Bridge, error::PersistenceError};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use std::{
    collections::{BTreeMap, HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tracing::{info, warn};
use veloren_ic_api as api;

fn io(context: &str) -> impl FnOnce(std::io::Error) -> PersistenceError + '_ {
    move |e| PersistenceError::OtherError(format!("{context}: {e}"))
}

/// World id in the realm canister (default 1).
pub const ENV_WORLD: &str = "VELOREN_REALM_WORLD";
/// Seconds between rtsim uploads (default 600; shutdown always uploads).
pub const ENV_SYNC: &str = "VELOREN_REALM_SYNC_SECS";
/// Shard name in the directory (default `Veloren shard <world>`).
pub const ENV_SHARD_NAME: &str = "VELOREN_REALM_SHARD_NAME";
/// Address players connect to (default `127.0.0.1:14004`).
pub const ENV_SHARD_ADDRESS: &str = "VELOREN_REALM_SHARD_ADDRESS";
/// Player cap shown in the directory (default 100).
pub const ENV_SHARD_MAX_PLAYERS: &str = "VELOREN_REALM_SHARD_MAX_PLAYERS";

/// This server's directory listing, from the environment.
pub fn shard_listing() -> api::RegisterShard {
    let world = world_id();
    api::RegisterShard {
        world,
        name: std::env::var(ENV_SHARD_NAME).unwrap_or_else(|_| format!("Veloren shard {}", world.0)),
        address: std::env::var(ENV_SHARD_ADDRESS).unwrap_or_else(|_| "127.0.0.1:14004".to_owned()),
        max_players: std::env::var(ENV_SHARD_MAX_PLAYERS)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100),
    }
}

pub fn world_id() -> api::WorldId {
    api::WorldId(
        std::env::var(ENV_WORLD)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1),
    )
}

pub fn sync_interval() -> Duration {
    Duration::from_secs(
        std::env::var(ENV_SYNC)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600),
    )
}

/// One bridge acting as the world's host, with the blob versions it last saw.
pub struct WorldStore {
    bridge: Bridge,
    world: api::WorldId,
    versions: HashMap<api::BlobKind, u64>,
}

impl WorldStore {
    /// Spawn a bridge and register this shard (claims the world on first use,
    /// updates the directory listing afterwards; gives the host its mint budget).
    pub fn open(thread: &'static str) -> Result<Self, PersistenceError> {
        let mut bridge = Bridge::spawn(thread, false)?;
        let listing = shard_listing();
        let world = listing.world;
        let registered: Result<(), api::ApiError> = bridge.call("register_shard", &listing)?;
        registered.map_err(|e| {
            PersistenceError::OtherError(format!(
                "shard {} cannot be registered by this host: {e:?} (another host owns this \
                 world id: set {ENV_WORLD}; or the listing is invalid: {ENV_SHARD_NAME}, \
                 {ENV_SHARD_ADDRESS}; or this host is frozen)",
                world.0
            ))
        })?;
        info!(
            world = world.0, name = %listing.name, address = %listing.address, thread,
            "shard registered on the realm"
        );
        Ok(Self {
            bridge,
            world,
            versions: HashMap::new(),
        })
    }

    /// Download and inflate a blob; `None` if the IC has none yet.
    pub fn get(&mut self, kind: api::BlobKind) -> Result<Option<Vec<u8>>, PersistenceError> {
        let started = Instant::now();
        let blob: Result<Option<api::Blob>, api::ApiError> =
            self.bridge.call("get_blob", api::BlobRef {
                world: self.world,
                kind,
            })?;
        let Some(blob) = blob.map_err(|e| PersistenceError::OtherError(format!("get_blob: {e:?}")))?
        else {
            self.versions.insert(kind, 0);
            return Ok(None);
        };
        self.versions.insert(kind, blob.version);
        let mut raw = Vec::new();
        DeflateDecoder::new(blob.bytes.as_slice())
            .read_to_end(&mut raw)
            .map_err(|e| PersistenceError::OtherError(format!("inflate {kind:?}: {e}")))?;
        info!(
            ?kind,
            version = blob.version,
            compressed = blob.bytes.len(),
            raw = raw.len(),
            ms = started.elapsed().as_millis(),
            "world blob loaded from realm"
        );
        Ok(Some(raw))
    }

    /// Deflate and upload a blob, replacing the stored version atomically.
    pub fn put(&mut self, kind: api::BlobKind, raw: &[u8]) -> Result<(), PersistenceError> {
        let started = Instant::now();
        if !self.versions.contains_key(&kind) {
            // First write in this process: learn the stored version.
            self.get(kind)?;
        }
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw).map_err(io("deflate"))?;
        let bytes = encoder.finish().map_err(io("deflate"))?;
        let compressed = bytes.len();
        let expected_version = self.versions[&kind];
        let stored: Result<u64, api::ApiError> =
            self.bridge.call("put_blob", api::PutBlob {
                world: self.world,
                kind,
                expected_version,
                bytes,
            })?;
        let version = stored.map_err(|e| {
            PersistenceError::OtherError(format!(
                "put_blob {kind:?} (expected version {expected_version}): {e:?}"
            ))
        })?;
        self.versions.insert(kind, version);
        info!(
            ?kind,
            version,
            raw = raw.len(),
            compressed,
            ms = started.elapsed().as_millis(),
            "world blob saved to realm"
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ server_config/

fn config_dir(data_dir: &Path) -> PathBuf { data_dir.join("server_config") }

/// The config directory's regular files as a sorted `[name, contents]` JSON archive.
fn pack(dir: &Path) -> Option<Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                files.insert(name, text);
            },
            Err(e) => warn!(%name, %e, "server_config file skipped (not UTF-8 text)"),
        }
    }
    serde_json::to_vec(&files).ok()
}

/// Before settings load: write the server_config files stored on the IC.
///
/// # Panics
/// When the realm is unreachable or the archive is corrupt: starting with
/// different settings than the world's would silently fork its state.
pub fn restore_server_config(data_dir: &Path) {
    let dir = config_dir(data_dir);
    let result = (|| -> Result<usize, PersistenceError> {
        let mut store = WorldStore::open("config")?;
        let Some(raw) = store.get(api::BlobKind::ServerConfig)? else {
            return Ok(0);
        };
        let files: BTreeMap<String, String> = serde_json::from_slice(&raw)?;
        std::fs::create_dir_all(&dir).map_err(io("create server_config"))?;
        for (name, text) in &files {
            // Names come from our own archive; still refuse anything path-like.
            if name.contains('/') || name.contains('\\') || name.starts_with('.') {
                warn!(%name, "server_config entry with a path-like name ignored");
                continue;
            }
            std::fs::write(dir.join(name), text).map_err(io("write server_config"))?;
        }
        Ok(files.len())
    })();
    match result {
        Ok(0) => info!(
            dir = %dir.display(),
            "no server_config on the realm yet; local files will be uploaded on the first sync"
        ),
        Ok(n) => info!(files = n, dir = %dir.display(), "server_config restored from the realm"),
        Err(e) => panic!("cannot restore server_config from the realm: {e}"),
    }
}

/// Uploads the server_config files when their contents change.
pub struct ConfigSync {
    dir: PathBuf,
    last: Option<u64>,
}

impl ConfigSync {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: config_dir(data_dir),
            last: None,
        }
    }

    pub fn sync(&mut self, store: &mut WorldStore) -> Result<(), PersistenceError> {
        let Some(archive) = pack(&self.dir) else {
            return Ok(());
        };
        let mut hasher = DefaultHasher::new();
        archive.hash(&mut hasher);
        let hash = hasher.finish();
        if self.last == Some(hash) {
            return Ok(());
        }
        if self.last.is_none()
            && store.get(api::BlobKind::ServerConfig)?.as_deref() == Some(archive.as_slice())
        {
            // First check after start-up: the realm already holds these exact files
            // (usually just restored from it), so an upload would only burn cycles.
            self.last = Some(hash);
            return Ok(());
        }
        store.put(api::BlobKind::ServerConfig, &archive)?;
        self.last = Some(hash);
        Ok(())
    }
}
