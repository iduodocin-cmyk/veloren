//! Child-process client for `realm-bridge` (canisters/realm/realm-bridge in the
//! veloren-ic repository). One process per persistence thread; calls are
//! synchronous because the loader/updater already run on their own threads.
//!
//! Every bridge signs as the world's host (Phase 3):
//! * `VELOREN_REALM_IDENTITY=<pem>`: the host's real key (Ed25519/secp256k1 PEM).
//! * otherwise the dev identity named `VELOREN_REALM_HOST` (default `dev-host`).
//!   Development only: anyone who knows the name can sign as it.
//!
//! The login bridge may also sign as a *player's* dev identity (`call_as`) when
//! `VELOREN_REALM_DEV_LOGIN=1`, so plain-username clients still work locally.

use crate::persistence::error::PersistenceError;
use veloren_ic_api as api;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::Instant,
};
use tracing::{debug, error, info, warn};

/// Path of the realm-bridge executable.
pub const ENV_BRIDGE: &str = "VELOREN_REALM_BRIDGE";
/// Connection file written by `make realm-dev` (REALM_URL / REALM_CANISTER / REALM_LOCAL).
pub const ENV_REALM: &str = "VELOREN_REALM_ENV";
/// PEM key of the host (production). Unset: dev identity `VELOREN_REALM_HOST`.
pub const ENV_IDENTITY: &str = "VELOREN_REALM_IDENTITY";
/// Dev identity name of the host when no PEM is given (default `dev-host`).
pub const ENV_HOST: &str = "VELOREN_REALM_HOST";
/// `1`: accept plain usernames and join the world for them with dev identities.
pub const ENV_DEV_LOGIN: &str = "VELOREN_REALM_DEV_LOGIN";

/// Whether plain-username logins are allowed (development only).
pub fn dev_login() -> bool { std::env::var(ENV_DEV_LOGIN).is_ok_and(|v| v == "1") }

/// `(bridge args, log label)` selecting the host identity.
fn host_identity() -> (Vec<String>, String) {
    match std::env::var(ENV_IDENTITY) {
        Ok(pem) if !pem.is_empty() => (vec!["--identity".into(), pem.clone()], format!("pem {pem}")),
        _ => {
            let name = std::env::var(ENV_HOST).unwrap_or_else(|_| "dev-host".to_owned());
            (vec!["--dev-identity".into(), name.clone()], format!("dev {name} (DEVELOPMENT ONLY)"))
        },
    }
}

pub struct Bridge {
    thread: &'static str,
    allow_dev_as: bool,
    /// Principal of the host identity this bridge signs with.
    pub me: api::PrincipalBytes,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

fn config(name: &str) -> Result<String, PersistenceError> {
    std::env::var(name).map_err(|_| {
        PersistenceError::OtherError(format!(
            "{name} is not set (required when VELOREN_PERSISTENCE=ic)"
        ))
    })
}

impl Bridge {
    /// Start a bridge signing as the host. `allow_dev_as` additionally lets
    /// `call_as` sign as players' dev identities (dev login only).
    pub fn spawn(thread: &'static str, allow_dev_as: bool) -> Result<Self, PersistenceError> {
        let program = config(ENV_BRIDGE)?;
        let realm = config(ENV_REALM)?;
        let (identity, identity_label) = host_identity();
        let mut command = Command::new(&program);
        command
            .args(["--env", &realm, "--name", thread])
            .args(&identity);
        if allow_dev_as {
            command.arg("--allow-dev-as");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                PersistenceError::OtherError(format!("{thread}: cannot start {program}: {e}"))
            })?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut bridge = Self {
            thread,
            allow_dev_as,
            me: api::PrincipalBytes(Vec::new()),
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        // The bridge connects (and, locally, fetches the root key) before it reads
        // stdin; a round trip proves it is up instead of failing on the first save.
        let me: Value = bridge.roundtrip(r#"{"id":0,"method":"whoami"}"#).map_err(|e| {
            PersistenceError::OtherError(format!(
                "{thread}: realm-bridge did not start ({e}); see its FATAL line above. For \
                 local development, is `make realm-dev` running?"
            ))
        })
        .and_then(|reply| Ok(serde_json::from_str(&reply)?))?;
        bridge.me = serde_json::from_value(me["ok"]["bytes"].clone())?;
        info!(
            %program, %realm, thread, pid = bridge.child.id(), identity = %identity_label,
            principal = %me["ok"]["principal"], dev_as = allow_dev_as, "realm-bridge ready"
        );
        Ok(bridge)
    }

    fn roundtrip(&mut self, line: &str) -> std::io::Result<String> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        let mut reply = String::new();
        if self.stdout.read_line(&mut reply)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "realm-bridge exited",
            ));
        }
        Ok(reply)
    }

    /// Call one realm method as the host and decode its reply.
    pub fn call<T: DeserializeOwned>(
        &mut self,
        method: &str,
        args: impl Serialize,
    ) -> Result<T, PersistenceError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(method, json!({ "id": id, "method": method, "args": args }).to_string())
    }

    /// Call one realm method signed by the dev identity `as_` (dev login only).
    pub fn call_as<T: DeserializeOwned>(
        &mut self,
        method: &str,
        as_: &str,
        args: impl Serialize,
    ) -> Result<T, PersistenceError> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "id": id, "method": method, "as": as_, "args": args }).to_string();
        self.send(method, line)
    }

    fn send<T: DeserializeOwned>(&mut self, method: &str, line: String) -> Result<T, PersistenceError> {
        let started = Instant::now();
        let reply = match self.roundtrip(&line) {
            Ok(reply) => reply,
            Err(e) => {
                // The child may have died (e.g. a panic); restart once and retry.
                warn!(thread = self.thread, method, error = %e, "realm-bridge I/O failed, restarting");
                let _ = self.child.kill();
                *self = Self::spawn(self.thread, self.allow_dev_as)?;
                self.roundtrip(&line).map_err(|e| {
                    PersistenceError::OtherError(format!("realm-bridge {method}: {e}"))
                })?
            },
        };
        let ms = started.elapsed().as_millis();
        let mut value: Value = serde_json::from_str(&reply)?;
        if let Some(err) = value.get("error") {
            error!(thread = self.thread, method, %err, ms, "realm call failed");
            return Err(PersistenceError::OtherError(format!("realm {method}: {err}")));
        }
        debug!(thread = self.thread, method, ms, "realm call ok");
        Ok(serde_json::from_value(value["ok"].take())?)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        // Closing stdin makes the bridge exit; reap it so no zombie is left.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
