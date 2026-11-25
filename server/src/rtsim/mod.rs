pub mod event;
pub mod rule;
pub mod tick;

use atomicwrites::{AtomicFile, OverwriteBehavior};
use common::{
    grid::Grid,
    mounting::VolumePos,
    rtsim::{ActorId, TerrainResource, WorldSettings},
    terrain::{CoordinateConversions, SpriteKind},
};
use common_ecs::{System, dispatch};
use common_state::BlockDiff;
use crossbeam_channel::{Receiver, Sender, unbounded};
use enum_map::EnumMap;
use rtsim::{
    RtState,
    data::{Data, ReadError, actor::SimulationMode},
    event::{OnDeath, OnHealthChange, OnHelped, OnMountVolume, OnSetup, OnTheft},
};
use specs::DispatcherBuilder;
use std::{
    fs::{self, File},
    io,
    path::PathBuf,
    thread::{self, JoinHandle},
    time::Instant,
};
use tracing::{debug, error, info, trace, warn};
use vek::*;
use world::{IndexRef, World};

pub struct RtSim {
    file_path: PathBuf,
    last_saved: Option<Instant>,
    state: RtState,
    save_thread: Option<(Sender<Data>, JoinHandle<()>)>,
}

impl RtSim {
    pub fn new(
        settings: &WorldSettings,
        index: IndexRef,
        world: &World,
        data_dir: PathBuf,
    ) -> Result<Self, ron::Error> {
        let file_path = Self::get_file_path(data_dir);

        let on_ic = crate::persistence::ic_enabled();
        if on_ic {
            info!("Looking for rtsim data on the Internet Computer realm...");
        } else {
            info!("Looking for rtsim data at {}...", file_path.display());
        }
        let data = 'load: {
            if std::env::var("RTSIM_NOLOAD").map_or(true, |v| v != "1") {
                // IC mode: the realm canister is the source of truth; no local file.
                let source: io::Result<Box<dyn io::Read>> = if on_ic {
                    match load_from_ic() {
                        Ok(Some(raw)) => Ok(Box::new(io::Cursor::new(raw))),
                        Ok(None) => Err(io::ErrorKind::NotFound.into()),
                        Err(e) => Err(io::Error::other(e)),
                    }
                } else {
                    File::open(&file_path)
                        .map(|file| Box::new(io::BufReader::new(file)) as Box<dyn io::Read>)
                };
                match source {
                    Ok(reader) => {
                        info!("Rtsim data found. Attempting to load...");

                        let ignore_version = std::env::var("RTSIM_IGNORE_VERSION").is_ok();

                        match Data::from_reader(reader) {
                            Err(ReadError::VersionMismatch(_)) if !ignore_version => {
                                warn!(
                                    "Rtsim data version mismatch (implying a breaking change), \
                                     rtsim data will be purged"
                                );
                            },
                            Ok(data) | Err(ReadError::VersionMismatch(data)) => {
                                info!("Rtsim data loaded.");
                                if data.should_purge {
                                    warn!(
                                        "The should_purge flag was set on the rtsim data, \
                                         generating afresh"
                                    );
                                } else {
                                    break 'load *data;
                                }
                            },
                            Err(ReadError::Load(err)) if on_ic => {
                                error!(
                                    "Rtsim data from the realm failed to load: {}; generating \
                                     afresh (the next sync replaces it)",
                                    err
                                );
                            },
                            Err(ReadError::Load(err)) => {
                                error!("Rtsim data failed to load: {}", err);
                                info!("Old rtsim data will now be moved to a backup file");
                                let mut i = 0;
                                loop {
                                    let mut backup_path = file_path.clone();
                                    backup_path.set_extension(if i == 0 {
                                        "ron_backup".to_string()
                                    } else {
                                        format!("ron_backup_{}", i)
                                    });
                                    if !backup_path.exists() {
                                        fs::rename(&file_path, &backup_path)?;
                                        warn!(
                                            "Failed rtsim data was moved to {}",
                                            backup_path.display()
                                        );
                                        info!("A fresh rtsim data will now be generated.");
                                        break;
                                    } else {
                                        info!(
                                            "Backup file {} already exists, trying another name...",
                                            backup_path.display()
                                        );
                                    }
                                    i += 1;
                                }
                            },
                        }
                    },
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        info!("No rtsim data found. Generating from world...")
                    },
                    Err(e) => return Err(e.into()),
                }
            } else {
                warn!(
                    "'RTSIM_NOLOAD' is set, skipping loading of rtsim state (old state will be \
                     overwritten)."
                );
            }

            let data = Data::generate(settings, world, index);
            info!("Rtsim data generated.");
            data
        };

        let mut this = Self {
            last_saved: None,
            state: RtState::new(data).with_resource(ChunkStates(Grid::populate_from(
                world.sim().get_size().as_(),
                |_| None,
            ))),
            file_path,
            save_thread: None,
        };

        rule::start_rules(&mut this.state);

        this.state.emit(OnSetup, &mut (), world, index);

        Ok(this)
    }

    fn get_file_path(mut data_dir: PathBuf) -> PathBuf {
        let mut path = std::env::var("VELOREN_RTSIM")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                data_dir.push("rtsim");
                data_dir
            });
        path.push("data.dat");
        path
    }

    pub fn hook_character_mount_volume(
        &mut self,
        world: &World,
        index: IndexRef,
        pos: VolumePos<ActorId>,
        actor: ActorId,
    ) {
        self.state
            .emit(OnMountVolume { actor, pos }, &mut (), world, index)
    }

    pub fn hook_pickup_owned_sprite(
        &mut self,
        world: &World,
        index: IndexRef,
        sprite: SpriteKind,
        wpos: Vec3<i32>,
        actor: ActorId,
    ) {
        let site = world.sim().get(wpos.xy().wpos_to_cpos()).and_then(|chunk| {
            chunk
                .sites
                .iter()
                .find_map(|site| self.state.data().sites.world_site_map.get(site).copied())
        });

        self.state.emit(
            OnTheft {
                actor,
                wpos,
                sprite,
                site,
            },
            &mut (),
            world,
            index,
        )
    }

    pub fn hook_load_chunk(
        &mut self,
        key: Vec2<i32>,
        max_res: EnumMap<TerrainResource, usize>,
        world: &World,
    ) {
        if let Some(chunk_state) = self.state.get_resource_mut::<ChunkStates>().0.get_mut(key) {
            *chunk_state = Some(LoadedChunkState { max_res });
        }

        if let Some(chunk) = world.sim().get(key) {
            let data = self.state.get_data_mut();
            for site in chunk.sites.iter() {
                let Some(site) = data.sites.world_site_map.get(site) else {
                    continue;
                };

                let site = *site;
                let Some(site) = data.sites.get_mut(site) else {
                    continue;
                };

                site.count_loaded_chunks += 1;
            }
        }
    }

    pub fn hook_unload_chunk(&mut self, key: Vec2<i32>, world: &World) {
        if let Some(chunk_state) = self.state.get_resource_mut::<ChunkStates>().0.get_mut(key) {
            *chunk_state = None;
        }

        if let Some(chunk) = world.sim().get(key) {
            let data = self.state.get_data_mut();
            for site in chunk.sites.iter() {
                let Some(site) = data.sites.world_site_map.get(site) else {
                    continue;
                };

                let site = *site;
                let Some(site) = data.sites.get_mut(site) else {
                    continue;
                };

                site.count_loaded_chunks = site.count_loaded_chunks.saturating_sub(1);
            }
        }
    }

    // Note that this hook only needs to be invoked if the block change results in a
    // change to the rtsim resource produced by [`Block::get_rtsim_resource`].
    pub fn hook_block_update(&mut self, world: &World, index: IndexRef, changes: Vec<BlockDiff>) {
        self.state
            .emit(event::OnBlockChange { changes }, &mut (), world, index);
    }

    pub fn hook_rtsim_entity_unload(&mut self, actor_id: ActorId) {
        let data = self.state.get_data_mut();

        if let Some(actor) = data.actors.get_mut(actor_id) {
            if matches!(actor.mode, SimulationMode::Simulated) {
                error!("Unloaded already unloaded entity");
            }
            actor.mode = SimulationMode::Simulated;
        }
    }

    pub fn hook_rtsim_actor_hp_change(
        &mut self,
        world: &World,
        index: IndexRef,
        actor: ActorId,
        cause: Option<ActorId>,
        new_hp_fraction: f32,
        change: f32,
    ) {
        self.state.emit(
            OnHealthChange {
                actor,
                cause,
                new_health_fraction: new_hp_fraction,
                change,
            },
            &mut (),
            world,
            index,
        )
    }

    pub fn hook_rtsim_actor_death(
        &mut self,
        world: &World,
        index: IndexRef,
        actor: ActorId,
        wpos: Option<Vec3<f32>>,
        killer: Option<ActorId>,
    ) {
        self.state.emit(
            OnDeath {
                wpos,
                actor,
                killer,
            },
            &mut (),
            world,
            index,
        );
    }

    pub fn hook_rtsim_actor_helped(
        &mut self,
        world: &World,
        index: IndexRef,
        actor: ActorId,
        saver: Option<ActorId>,
    ) {
        self.state
            .emit(OnHelped { actor, saver }, &mut (), world, index);
    }

    pub fn save(&mut self, wait_until_finished: bool) {
        debug!("Saving rtsim data...");

        // Create the save thread if it doesn't already exist
        // We're not using the slow job pool here for two reasons:
        // 1) The thread is mostly blocked on IO, not compute
        // 2) We need to synchronise saves to ensure monotonicity, which slow jobs
        // aren't designed to allow
        let (tx, _) = self.save_thread.get_or_insert_with(|| {
            trace!("Starting rtsim data save thread...");
            let (tx, rx) = unbounded();
            let file_path = self.file_path.clone();
            if crate::persistence::ic_enabled() {
                (tx, thread::spawn(move || ic_save_thread(file_path, rx)))
            } else {
                (tx, thread::spawn(move || save_thread(file_path, rx)))
            }
        });

        // Send rtsim data to the save thread
        if let Err(err) = tx.send(self.state.data().clone()) {
            error!("Failed to perform rtsim save: {}", err);
        }

        // If we need to wait until the save thread has done its work (due to, for
        // example, server shutdown) then do that.
        if wait_until_finished && let Some((tx, handle)) = self.save_thread.take() {
            drop(tx);
            info!("Waiting for rtsim save thread to finish...");
            handle.join().expect("Save thread failed to join");
            info!("Rtsim save thread finished.");
        }

        self.last_saved = Some(Instant::now());
    }

    // TODO: Clean up this API a bit
    pub fn get_chunk_resources(&self, key: Vec2<i32>) -> EnumMap<TerrainResource, f32> {
        self.state
            .data()
            .nature
            .chunk_resources(key)
            .copied()
            .unwrap_or_default()
    }

    pub fn state(&self) -> &RtState { &self.state }

    pub fn set_should_purge(&mut self, should_purge: bool) {
        self.state.data_mut().should_purge = should_purge;
    }
}

fn save_thread(file_path: PathBuf, rx: Receiver<Data>) {
    if let Some(dir) = file_path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    let atomic_file = AtomicFile::new(file_path, OverwriteBehavior::AllowOverwrite);
    while let Ok(data) = rx.recv() {
        debug!("Writing rtsim data to file...");
        match atomic_file.write(move |file| data.write_to(io::BufWriter::new(file))) {
            Ok(_) => debug!("Rtsim data saved."),
            Err(e) => error!("Saving rtsim data failed: {}", e),
        }
    }
}

/// Set when rtsim data was loaded from the realm: the save thread then waits a
/// full interval before its first upload instead of re-sending identical data.
static LOADED_FROM_IC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn load_from_ic() -> Result<Option<Vec<u8>>, String> {
    use crate::persistence::world::WorldStore;
    let mut store = WorldStore::open("rtsim-load").map_err(|e| e.to_string())?;
    let raw = store
        .get(veloren_ic_api::BlobKind::Rtsim)
        .map_err(|e| e.to_string())?;
    LOADED_FROM_IC.store(raw.is_some(), std::sync::atomic::Ordering::Relaxed);
    Ok(raw)
}

/// IC mode: keep the newest rtsim data and upload it every
/// `VELOREN_REALM_SYNC_SECS` and on shutdown (when the sender is dropped);
/// server_config files are uploaded alongside when they changed. Nothing is
/// written to disk.
fn ic_save_thread(file_path: PathBuf, rx: Receiver<Data>) {
    use crate::persistence::world::{ConfigSync, WorldStore, sync_interval};
    use crossbeam_channel::RecvTimeoutError;
    use std::time::Duration;

    // file_path = <data_dir>/rtsim/data.dat
    let data_dir = file_path
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_default();
    let mut store = match WorldStore::open("rtsim") {
        Ok(store) => store,
        Err(e) => {
            error!("Rtsim sync to the realm is unavailable, world state will NOT be saved: {}", e);
            while rx.recv().is_ok() {}
            return;
        },
    };
    let mut config = ConfigSync::new(&data_dir);
    let interval = sync_interval();
    info!(secs = interval.as_secs(), "Rtsim data syncs to the realm");
    let upload = |store: &mut WorldStore, data: Data, config: &mut ConfigSync| {
        let mut raw = Vec::new();
        match data.write_to(&mut raw) {
            Ok(()) => {
                if let Err(e) = store.put(veloren_ic_api::BlobKind::Rtsim, &raw) {
                    error!("Saving rtsim data to the realm failed: {}", e);
                }
            },
            Err(e) => error!("Serializing rtsim data failed: {}", e),
        }
        if let Err(e) = config.sync(store) {
            error!("Saving server_config to the realm failed: {}", e);
        }
    };
    let mut pending = None;
    // Fresh worlds upload at the first save; worlds just loaded from the realm wait.
    let mut last_upload = LOADED_FROM_IC
        .load(std::sync::atomic::Ordering::Relaxed)
        .then(Instant::now);
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(data) => pending = Some(data),
            Err(RecvTimeoutError::Timeout) => {},
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if pending.is_some() && last_upload.is_none_or(|t| t.elapsed() >= interval) {
            upload(&mut store, pending.take().expect("checked"), &mut config);
            last_upload = Some(Instant::now());
        }
    }
    // Shutdown (`save(true)` dropped the sender): always persist the latest state.
    if let Some(data) = pending {
        info!("Uploading final rtsim data to the realm...");
        upload(&mut store, data, &mut config);
    }
}

pub struct ChunkStates(pub Grid<Option<LoadedChunkState>>);

pub struct LoadedChunkState {
    // The maximum possible number of each resource in this chunk
    pub max_res: EnumMap<TerrainResource, usize>,
}

pub fn add_server_systems(dispatch_builder: &mut DispatcherBuilder) {
    dispatch::<tick::Sys>(dispatch_builder, &[&common_systems::phys::Sys::sys_name()]);
}
