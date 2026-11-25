//! Child-process client for `realm-bridge` (canisters/realm/realm-bridge in the
//! veloren-ic repository). One process per persistence thread; calls are
//! synchronous because the loader/updater already run on their own threads.

use crate::persistence::error::PersistenceError;
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

pub struct Bridge {
    thread: &'static str,
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
    pub fn spawn(thread: &'static str) -> Result<Self, PersistenceError> {
        let program = config(ENV_BRIDGE)?;
        let realm = config(ENV_REALM)?;
        // Phase 2: players act through deterministic dev identities (`as`). Phase 3
        // replaces this with Internet Identity and host grants.
        let mut child = Command::new(&program)
            .args(["--env", &realm, "--allow-dev-as", "--name", thread])
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
        info!(
            %program, %realm, thread, pid = bridge.child.id(),
            principal = %me["ok"]["principal"], "realm-bridge ready"
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

    /// Call one realm method as player `as_` and decode its reply.
    pub fn call<T: DeserializeOwned>(
        &mut self,
        method: &str,
        as_: &str,
        args: impl Serialize,
    ) -> Result<T, PersistenceError> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "id": id, "method": method, "as": as_, "args": args }).to_string();
        let started = Instant::now();
        let reply = match self.roundtrip(&line) {
            Ok(reply) => reply,
            Err(e) => {
                // The child may have died (e.g. a panic); restart once and retry.
                warn!(thread = self.thread, method, error = %e, "realm-bridge I/O failed, restarting");
                let _ = self.child.kill();
                *self = Self::spawn(self.thread)?;
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
