//! Internet Computer persistence backend (`VELOREN_PERSISTENCE=ic`).
//!
//! Replaces the SQLite statements of `character/mod.rs` with calls to the
//! realm canister through `realm-bridge`, reusing this module's conversions so
//! stored strings are byte-identical to what SQLite stored. SQLite is never
//! opened in this mode.
//!
//! Differences from the SQLite backend, by design:
//! * Item ids are `(character << 32) | local` (see `veloren_ic_api::item_id`), so
//!   they stay globally unique with no shared sequence. Pseudo-containers are
//!   the fixed ids 1–4 and are not stored as rows.
//! * Saves send only what changed since the last load/save (a per-character
//!   baseline shared by the loader and updater threads), not a full rewrite.
//! * Identity (Phase 3): the server signs as the world's host. A player logs in
//!   with `ic:<nonce>:<name>`, which their own client registered with
//!   `join_world`; `login` redeems it (once) for the player's verified principal.
//!   The player's Veloren uuid is derived from that principal, and every character
//!   call is a `host_*` call on the player's behalf. All of a host's saves go in
//!   one `batch_update` per flush (split only by message size).
//!
//! See docs/veloren-persistence-seam.md in the veloren-ic repository.

mod bridge;

pub use bridge::Bridge;

use super::{
    convert_waypoint_or_warn,
    conversions::{
        convert_active_abilities_from_database, convert_active_abilities_to_database,
        convert_body_from_database, convert_body_to_database_json,
        convert_character_from_database, convert_hardcore_from_database,
        convert_hardcore_to_database, convert_inventory_from_database_items,
        convert_items_to_database_items, convert_loadout_from_database_items,
        convert_recipe_book_from_database_items, convert_skill_groups_to_database,
        convert_skill_set_from_database, convert_stats_from_database,
        convert_waypoint_to_database_json,
    },
};
use crate::persistence::{
    EditableComponents, PersistedComponents,
    character_loader::{CharacterCreationResult, CharacterDataResult, CharacterListResult},
    character_updater::PetPersistenceData,
    error::PersistenceError,
    models,
};
use common::{
    character::{CharacterId, CharacterItem},
    comp::{self, Content, Inventory, MapMarker, Waypoint},
    event::{PermanentChange, UpdateCharacterMetadata},
    npc::NPC_NAMES,
};
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroU64,
    sync::{LazyLock, Mutex},
};
use tracing::{debug, info, warn};
use veloren_ic_api as api;

pub use bridge::dev_login;

/// `VELOREN_PERSISTENCE=ic` selects this backend.
pub fn enabled() -> bool { std::env::var("VELOREN_PERSISTENCE").is_ok_and(|v| v == "ic") }

// Fixed pseudo-container ids (api::INVENTORY_CONTAINER …).
const INVENTORY: i64 = api::INVENTORY_CONTAINER.0 as i64;
const LOADOUT: i64 = api::LOADOUT_CONTAINER.0 as i64;
const OVERFLOW: i64 = api::OVERFLOW_CONTAINER.0 as i64;
const RECIPE_BOOK: i64 = api::RECIPE_BOOK_CONTAINER.0 as i64;

/// What the canister holds for a character, as of the last load or save.
#[derive(Clone)]
struct Baseline {
    revision: api::Revision,
    character: api::CharacterRow,
    items: BTreeMap<u64, api::ItemRow>,
    skill_groups: Vec<api::SkillGroupRow>,
    pets: Vec<api::PetRow>,
    ability_sets: String,
}

/// Shared by the loader (writes on load) and updater (reads/writes on save).
static BASELINES: LazyLock<Mutex<HashMap<i64, Baseline>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn baselines() -> std::sync::MutexGuard<'static, HashMap<i64, Baseline>> {
    BASELINES.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ------------------------------------------------------------------ players

/// Veloren player uuid (as a string) → the principal that logged in with it.
/// Filled by `login`; the persistence threads look players up here.
static PLAYERS: LazyLock<Mutex<HashMap<String, api::PrincipalBytes>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn world() -> api::WorldId { crate::persistence::world::world_id() }

fn player(uuid: &str) -> Result<api::PrincipalBytes, PersistenceError> {
    PLAYERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(uuid)
        .cloned()
        .ok_or_else(|| {
            PersistenceError::OtherError(format!(
                "player {uuid} has no verified Internet Computer login on this server"
            ))
        })
}

/// A verified login: who the player is and the name they chose.
pub struct Login {
    pub principal: api::PrincipalBytes,
    pub principal_text: String,
    pub name: String,
}

/// Verify a login string on the login bridge.
/// * `ic:<nonce>:<name>`: redeem the player's `join_world` nonce (single use).
/// * a plain username, only with `VELOREN_REALM_DEV_LOGIN=1`: join the world as
///   that name's dev identity first, then redeem, so dev logins take the same path.
pub fn login(bridge: &mut Bridge, username_or_token: &str) -> Result<Login, String> {
    let token = if api::parse_session_token(username_or_token).is_some() {
        username_or_token.to_owned()
    } else if dev_login() {
        let name = username_or_token;
        let host = bridge.me.clone();
        let reply: serde_json::Value = bridge
            .call_as("login", name, serde_json::json!({
                "world": world(),
                "host": host,
                "name": name,
            }))
            .map_err(|e| format!("dev login for {name:?} failed: {e}"))?;
        warn!(name, "DEV LOGIN: joined the world with a name-derived identity (not secure)");
        reply["token"]
            .as_str()
            .ok_or_else(|| format!("dev login: unexpected reply {reply}"))?
            .to_owned()
    } else {
        return Err("This server uses Internet Computer login. Update your client, or set \
                    VELOREN_REALM_DEV_LOGIN=1 on the server for local development."
            .to_owned());
    };
    let reply: serde_json::Value = bridge
        .call("redeem", serde_json::json!({ "world": world(), "token": token }))
        .map_err(|e| format!("login refused: {e}"))?;
    let principal: api::PrincipalBytes = serde_json::from_value(reply["player"].clone())
        .map_err(|e| format!("login: bad reply {reply}: {e}"))?;
    Ok(Login {
        principal,
        principal_text: reply["principal"].as_str().unwrap_or_default().to_owned(),
        name: reply["name"].as_str().unwrap_or_default().to_owned(),
    })
}

/// Remember which principal a Veloren uuid stands for (after `login`).
pub fn register_player(uuid: &str, principal: api::PrincipalBytes) {
    PLAYERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(uuid.to_owned(), principal);
}

// ------------------------------------------------------------------ conversions

fn api_error(context: &str, e: api::ApiError) -> PersistenceError {
    match e {
        api::ApiError::LimitExceeded(api::Limit::CharactersPerPlayer) => {
            PersistenceError::CharacterLimitReached
        },
        api::ApiError::NotFound => PersistenceError::CharacterDataError,
        other => PersistenceError::OtherError(format!("realm {context}: {other:?}")),
    }
}

fn to_api_item(m: &models::Item) -> api::ItemRow {
    api::ItemRow {
        item_id: api::ItemId(m.item_id as u64),
        parent_container_item_id: api::ItemId(m.parent_container_item_id as u64),
        item_definition_id: m.item_definition_id.clone(),
        stack_size: u32::try_from(m.stack_size).unwrap_or(u32::MAX),
        position: m.position.clone(),
        properties: m.properties.clone(),
    }
}

fn to_model_item(r: &api::ItemRow) -> models::Item {
    models::Item {
        item_id: r.item_id.0 as i64,
        parent_container_item_id: r.parent_container_item_id.0 as i64,
        item_definition_id: r.item_definition_id.clone(),
        stack_size: i64::from(r.stack_size),
        position: r.position.clone(),
        properties: r.properties.clone(),
    }
}

fn to_api_skill(m: models::SkillGroup) -> api::SkillGroupRow {
    api::SkillGroupRow {
        skill_group_kind: m.skill_group_kind,
        earned_exp: m.earned_exp,
        spent_exp: m.spent_exp,
        skills: m.skills,
        hash_val: m.hash_val,
    }
}

/// Items whose parent chain reaches `root` (what SQLite's recursive `load_items` returned).
fn subtree(items: &[api::ItemRow], root: i64) -> Vec<models::Item> {
    let parent: HashMap<u64, u64> = items
        .iter()
        .map(|i| (i.item_id.0, i.parent_container_item_id.0))
        .collect();
    items
        .iter()
        .filter(|i| {
            let mut id = i.item_id.0;
            for _ in 0..=parent.len() {
                match parent.get(&id) {
                    Some(&p) if p == root as u64 => return true,
                    Some(&p) => id = p,
                    None => return false,
                }
            }
            false
        })
        .map(to_model_item)
        .collect()
}

fn character_model(id: i64, uuid: &str, row: &api::CharacterRow) -> models::Character {
    models::Character {
        character_id: id,
        player_uuid: uuid.to_owned(),
        alias: row.alias.clone(),
        waypoint: row.waypoint.clone(),
        hardcore: i64::from(row.hardcore),
    }
}

fn pet_rows(pets: &[PetPersistenceData], next: &mut u64) -> Result<Vec<api::PetRow>, PersistenceError> {
    pets.iter()
        .map(|(pet, body, _stats)| {
            let ids = pet.get_database_id();
            let id = match ids.load() {
                Some(id) => id.get(),
                None => {
                    let id = *next;
                    *next += 1;
                    ids.store(NonZeroU64::new(id));
                    id
                },
            };
            let (variant, data) = convert_body_to_database_json(body)?;
            Ok(api::PetRow {
                database_id: id,
                // TODO (upstream): pet names are not persisted yet; SQLite stores "" too.
                name: String::new(),
                body_variant: variant.to_owned(),
                body_data: data,
            })
        })
        .collect()
}

// ------------------------------------------------------------------ loader

pub fn load_character_list(bridge: &mut Bridge, uuid: &str) -> CharacterListResult {
    let list: Result<Vec<api::CharacterSummary>, api::ApiError> =
        bridge.call("host_list_characters", api::HostPlayer {
            world: world(),
            player: player(uuid)?,
        })?;
    list.map_err(|e| api_error("host_list_characters", e))?
        .into_iter()
        .map(|s| {
            let id = s.id.0 as i64;
            let model = character_model(id, uuid, &s.character);
            let body = convert_body_from_database(&s.body.variant, &s.body.body_data)?;
            let hardcore = convert_hardcore_from_database(model.hardcore)?;
            let loadout =
                convert_loadout_from_database_items(LOADOUT, &subtree(&s.preview_items, LOADOUT))?;
            let (recipe_book, _) =
                convert_recipe_book_from_database_items(&subtree(&s.preview_items, RECIPE_BOOK))?;
            let (waypoint, _) =
                convert_waypoint_or_warn(model.waypoint.as_deref(), CharacterId(id));
            Ok(CharacterItem {
                character: convert_character_from_database(&model),
                body,
                hardcore: hardcore.is_some(),
                inventory: Inventory::with_loadout(loadout, body).with_recipe_book(recipe_book),
                location: waypoint.map(|w| w.get_pos()),
            })
        })
        .collect()
}

pub fn load_character_data(
    bridge: &mut Bridge,
    uuid: String,
    char_id: CharacterId,
) -> CharacterDataResult {
    let snap: Result<api::CharacterSnapshot, api::ApiError> =
        bridge.call("host_load_character", api::HostCharacter {
            world: world(),
            id: api::CharacterId(char_id.0 as u64),
        })?;
    let snap = snap.map_err(|e| api_error("host_load_character", e))?;
    // The host may only touch characters of players who joined with it, but make
    // sure this one belongs to the player asking for it.
    if snap.owner != player(&uuid)? {
        warn!(char = char_id.0, %uuid, "character belongs to another player");
        return Err(PersistenceError::CharacterDataError);
    }

    let model = character_model(char_id.0, &uuid, &snap.character);
    let (waypoint, map_marker): (Option<Waypoint>, Option<MapMarker>) =
        convert_waypoint_or_warn(model.waypoint.as_deref(), char_id);
    let skill_groups: Vec<models::SkillGroup> = snap
        .skill_groups
        .iter()
        .map(|g| models::SkillGroup {
            entity_id: char_id.0,
            skill_group_kind: g.skill_group_kind.clone(),
            earned_exp: g.earned_exp,
            spent_exp: g.spent_exp,
            skills: g.skills.clone(),
            hash_val: g.hash_val.clone(),
        })
        .collect();
    let pets = snap
        .pets
        .iter()
        .filter_map(|p| {
            let Ok(body) = convert_body_from_database(&p.body_variant, &p.body_data) else {
                warn!(pet = p.database_id, char = char_id.0, "failed to deserialize pet body");
                return None;
            };
            let pet = comp::Pet::new_from_database(NonZeroU64::new(p.database_id)?);
            let stats = comp::Stats::new(
                NPC_NAMES
                    .read()
                    .get_default_name(&body)
                    .unwrap_or(Content::Plain(String::new())),
                body,
            );
            Some((pet, body, stats))
        })
        .collect();
    let abilities = models::AbilitySets {
        entity_id: char_id.0,
        ability_sets: snap.ability_sets.ability_sets.clone(),
    };
    let (skill_set, skill_set_persistence_load_error) =
        convert_skill_set_from_database(&skill_groups);
    let body = convert_body_from_database(&snap.body.variant, &snap.body.body_data)?;
    let inventory = convert_inventory_from_database_items(
        INVENTORY,
        &subtree(&snap.items, INVENTORY),
        LOADOUT,
        &subtree(&snap.items, LOADOUT),
        OVERFLOW,
        &subtree(&snap.items, OVERFLOW),
        &subtree(&snap.items, RECIPE_BOOK),
    )?;
    let components = PersistedComponents {
        body,
        hardcore: convert_hardcore_from_database(model.hardcore)?,
        stats: convert_stats_from_database(model.alias.clone(), body),
        skill_set,
        inventory,
        waypoint,
        pets,
        active_abilities: convert_active_abilities_from_database(&abilities),
        map_marker,
    };

    baselines().insert(char_id.0, Baseline {
        revision: snap.revision,
        character: snap.character,
        items: snap.items.into_iter().map(|i| (i.item_id.0, i)).collect(),
        skill_groups: snap.skill_groups,
        pets: snap.pets,
        ability_sets: snap.ability_sets.ability_sets,
    });
    info!(char = char_id.0, revision = %snap.revision.0, "loaded character from realm");
    Ok((components, UpdateCharacterMetadata {
        skill_set_persistence_load_error,
    }))
}

// ------------------------------------------------------------------ character screen

pub fn create_character(
    bridge: &mut Bridge,
    uuid: &str,
    alias: &str,
    components: PersistedComponents,
) -> CharacterCreationResult {
    let PersistedComponents {
        body,
        hardcore,
        skill_set,
        inventory,
        waypoint,
        active_abilities,
        map_marker,
        ..
    } = components;
    // Local ids from FIRST_LOCAL_ITEM_ID; the canister prefixes them with the new id.
    let mut next = api::FIRST_LOCAL_ITEM_ID as i64;
    let items = convert_items_to_database_items(
        LOADOUT, &inventory, INVENTORY, OVERFLOW, RECIPE_BOOK, &mut next,
    )
    .iter()
    .map(|pair| to_api_item(&pair.model))
    .collect();
    let (variant, body_data) = convert_body_to_database_json(&body)?;
    let new = api::NewCharacter {
        character: api::CharacterRow {
            alias: alias.to_owned(),
            waypoint: convert_waypoint_to_database_json(waypoint, map_marker),
            hardcore: convert_hardcore_to_database(hardcore) != 0,
        },
        body: api::BodyRow {
            variant: variant.to_owned(),
            body_data,
        },
        items,
        skill_groups: convert_skill_groups_to_database(CharacterId(0), skill_set.skill_groups())
            .into_iter()
            .map(to_api_skill)
            .collect(),
        ability_sets: api::AbilitySetsRow {
            ability_sets: convert_active_abilities_to_database(CharacterId(0), &active_abilities)
                .ability_sets,
        },
    };
    let created: Result<api::CharacterId, api::ApiError> =
        bridge.call("host_create_character", api::HostCreate {
            world: world(),
            player: player(uuid)?,
            new,
        })?;
    let id = created.map_err(|e| api_error("host_create_character", e))?;
    info!(char = id.0, uuid, "created character in realm");
    load_character_list(bridge, uuid).map(|list| (CharacterId(id.0 as i64), list))
}

pub fn edit_character(
    bridge: &mut Bridge,
    (body,): EditableComponents,
    trusted_change: Option<PermanentChange>,
    character_id: CharacterId,
    uuid: &str,
    alias: Option<&str>,
) -> CharacterCreationResult {
    let list = load_character_list(bridge, uuid)?;
    let current = list
        .iter()
        .find(|c| c.character.id == Some(character_id))
        .ok_or(PersistenceError::CharacterDataError)?;
    // Same validation as the SQLite backend.
    if let (comp::Body::Humanoid(new), comp::Body::Humanoid(old)) = (body, current.body) {
        let allowed = match trusted_change {
            Some(change) => change.expected_old_body == current.body,
            None => new.species == old.species && new.body_type == old.body_type,
        };
        if !allowed {
            warn!(char = character_id.0, ?alias, "character edit rejected by validation");
            return Err(PersistenceError::CharacterDataError);
        }
    }
    let (variant, body_data) = convert_body_to_database_json(&body)?;
    let edit = api::EditCharacter {
        id: api::CharacterId(character_id.0 as u64),
        alias: alias.map_or_else(|| current.character.alias.clone(), str::to_owned),
        body: api::BodyRow {
            variant: variant.to_owned(),
            body_data,
        },
    };
    let revision: Result<api::Revision, api::ApiError> =
        bridge.call("host_edit_character", api::HostEdit {
            world: world(),
            edit,
        })?;
    revision.map_err(|e| api_error("host_edit_character", e))?;
    // The revision moved; the next save reloads the baseline.
    baselines().remove(&character_id.0);
    load_character_list(bridge, uuid).map(|list| (character_id, list))
}

// ------------------------------------------------------------------ updater

/// Permanently delete a character. Like SQLite, a missing or foreign character is ignored.
pub fn delete_character(
    bridge: &mut Bridge,
    uuid: &str,
    char_id: CharacterId,
) -> Result<(), PersistenceError> {
    // The character must be one of this player's (it is in their list).
    let mine = load_character_list(bridge, uuid)?
        .iter()
        .any(|c| c.character.id == Some(char_id));
    if !mine {
        warn!(char = char_id.0, uuid, "delete ignored: not one of this player's characters");
        return Ok(());
    }
    let deleted: Result<(), api::ApiError> =
        bridge.call("host_delete_character", api::HostCharacter {
            world: world(),
            id: api::CharacterId(char_id.0 as u64),
        })?;
    match deleted {
        Ok(()) | Err(api::ApiError::NotFound | api::ApiError::NotAuthorized) => {
            baselines().remove(&char_id.0);
            Ok(())
        },
        Err(e) => Err(api_error("host_delete_character", e)),
    }
}

/// A computed save: the delta to send and the baseline to keep if it is applied.
pub struct PendingSave {
    char_id: i64,
    delta: api::CharacterDelta,
    after: Baseline,
}

/// Build the delta for one character save. `None` when nothing changed.
pub fn prepare_save(
    char_id: CharacterId,
    skill_set: &comp::SkillSet,
    inventory: &Inventory,
    pets: &[PetPersistenceData],
    waypoint: Option<comp::Waypoint>,
    active_abilities: &comp::ability::ActiveAbilities,
    map_marker: Option<comp::MapMarker>,
) -> Result<Option<PendingSave>, PersistenceError> {
    let Some(before) = baselines().get(&char_id.0).cloned() else {
        return Err(PersistenceError::OtherError(format!(
            "character {} was not loaded through the ic backend; cannot diff its save",
            char_id.0
        )));
    };
    let character = api::CharacterId(char_id.0 as u64);

    // Ids: everything this character already uses, items and pets.
    let used = before
        .items
        .keys()
        .copied()
        .chain(before.pets.iter().map(|p| p.database_id));
    let mut next = api::next_item_id(character, used);
    let mut next_i64 = next as i64;
    let items: BTreeMap<u64, api::ItemRow> = convert_items_to_database_items(
        LOADOUT, inventory, INVENTORY, OVERFLOW, RECIPE_BOOK, &mut next_i64,
    )
    .iter()
    .map(|pair| to_api_item(&pair.model))
    .map(|row| (row.item_id.0, row))
    .collect();
    next = next.max(next_i64 as u64);

    let upsert: Vec<api::ItemRow> = items
        .values()
        .filter(|row| before.items.get(&row.item_id.0) != Some(row))
        .cloned()
        .collect();
    let delete: Vec<api::ItemId> = before
        .items
        .keys()
        .filter(|id| !items.contains_key(id))
        .map(|&id| api::ItemId(id))
        .collect();

    let skill_groups: Vec<api::SkillGroupRow> =
        convert_skill_groups_to_database(char_id, skill_set.skill_groups())
            .into_iter()
            .map(to_api_skill)
            .collect();
    let pets = pet_rows(pets, &mut next)?;
    let row = api::CharacterRow {
        waypoint: convert_waypoint_to_database_json(waypoint, map_marker),
        ..before.character.clone()
    };
    let ability_sets =
        convert_active_abilities_to_database(char_id, active_abilities).ability_sets;

    let delta = api::CharacterDelta {
        id: character,
        expected_revision: before.revision,
        character: (row != before.character).then(|| row.clone()),
        items: (!upsert.is_empty() || !delete.is_empty()).then(|| api::ItemsPatch {
            upsert: upsert.clone(),
            delete: delete.clone(),
        }),
        skill_groups: (skill_groups != before.skill_groups).then(|| skill_groups.clone()),
        pets: (pets != before.pets).then(|| pets.clone()),
        ability_sets: (ability_sets != before.ability_sets).then(|| api::AbilitySetsRow {
            ability_sets: ability_sets.clone(),
        }),
    };
    if delta.is_empty() {
        debug!(char = char_id.0, "save skipped: nothing changed");
        return Ok(None);
    }
    debug!(
        char = char_id.0,
        upsert = upsert.len(),
        delete = delete.len(),
        "save prepared"
    );
    let after = Baseline {
        character: row,
        items,
        skill_groups,
        pets,
        ability_sets,
        ..before
    };
    Ok(Some(PendingSave {
        char_id: char_id.0,
        delta,
        after,
    }))
}

/// Batches stay under this many bytes of JSON (JSON is never smaller than the
/// IC Wire encoding the bridge sends), leaving headroom for the envelope.
const BATCH_JSON_BYTES: usize = api::MAX_BATCH_BYTES - 64 * 1024;

/// Split saves into batches that each fit one ingress message.
fn split_by_size(saves: Vec<PendingSave>) -> Vec<Vec<PendingSave>> {
    let mut batches: Vec<Vec<PendingSave>> = Vec::new();
    let mut bytes = 0;
    for save in saves {
        let size = serde_json::to_vec(&save.delta).map_or(BATCH_JSON_BYTES, |v| v.len());
        match batches.last_mut() {
            Some(batch) if bytes + size <= BATCH_JSON_BYTES => {
                bytes += size;
                batch.push(save);
            },
            _ => {
                bytes = size;
                batches.push(vec![save]);
            },
        }
    }
    batches
}

/// Send prepared saves of all players as the host: one `batch_update` per
/// flush (more only if it would not fit one message). Any rejection that is not
/// a replay of an applied save is an error, so the caller can apply Veloren's
/// usual "disconnect everyone" integrity policy.
pub fn commit_saves(
    bridge: &mut Bridge,
    batch_id: u64,
    saves: Vec<PendingSave>,
) -> Result<(), PersistenceError> {
    let mut failures = Vec::new();
    let batches = split_by_size(saves);
    let parts = batches.len();
    for (part, saves) in batches.into_iter().enumerate() {
        let batch = api::BatchUpdate {
            world: world(),
            batch_id,
            deltas: saves.iter().map(|s| s.delta.clone()).collect(),
        };
        debug!(batch_id, part = part + 1, parts, characters = saves.len(), "sending batch_update");
        let result: api::BatchResult = bridge.call("batch_update", batch)?;
        for save in saves {
            let id = save.delta.id;
            let applied = result.applied.iter().find(|a| a.id == id).map(|a| a.revision);
            let replay = result
                .rejected
                .iter()
                .find(|r| r.id == id)
                .filter(|r| r.reason.is_replay_of(save.delta.expected_revision))
                .map(|_| api::Revision(save.delta.expected_revision.0 + 1));
            match applied.or(replay) {
                Some(revision) => {
                    baselines().insert(save.char_id, Baseline {
                        revision,
                        ..save.after
                    });
                },
                None => {
                    let reason = result.rejected.iter().find(|r| r.id == id);
                    failures.push(format!("character {}: {:?}", save.char_id, reason));
                    // Force a reload before the next save of this character.
                    baselines().remove(&save.char_id);
                },
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(PersistenceError::OtherError(format!(
            "realm batch_update rejected: {}",
            failures.join("; ")
        )))
    }
}
