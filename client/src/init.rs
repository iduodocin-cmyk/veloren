//! Code and utils for Initializing the connection to the server.
use std::sync::Arc;

use common_net::msg::ServerInfo;
use network::{ConnectAddr, Network};
use rustls::client::danger::ServerCertVerified;
use tracing::{info, warn};
use veloren_ic_api as ic;

use crate::{Error, addr};

#[derive(Clone)]
pub enum Credentials {
    UsernamePassword(String, String),
    Username(String),
}

pub trait CredentialProvider {
    ///provides a quick check to verify if a Auth Server is expected and
    /// trusted This function is expected to return quickly.
    fn auth_trusted(&self, auth_provider: &Option<String>) -> bool;

    ///Called by the client once we are connected to the server and the server
    /// is requiring us to provide Credentials.
    /// This function is expected to trigger UI to wait for a result. So the
    /// User might take a minute or so to log in.
    /// Throw Error in case you want to abort login.
    fn get_credentials(
        &self,
        auth_provider: &Option<String>,
    ) -> impl std::future::Future<Output = Result<Credentials, ()>> + Send;
}

/// Use in case you already know your Auth provider Username and Password
/// upfront.
#[derive(Default)]
pub struct StaticCredentialProvider {
    pub credentials_by_auth: std::collections::HashMap<Option<String>, Credentials>,
}

impl CredentialProvider for StaticCredentialProvider {
    fn auth_trusted(&self, auth_provider: &Option<String>) -> bool {
        self.credentials_by_auth.contains_key(auth_provider)
    }

    async fn get_credentials(&self, auth_provider: &Option<String>) -> Result<Credentials, ()> {
        self.credentials_by_auth
            .get(auth_provider)
            .cloned()
            .ok_or(())
    }
}

#[derive(Debug)]
pub enum ClientInitStage {
    /// A connection to the server is being created
    ConnectionEstablish,
    /// Waiting for server version
    WatingForServerVersion,
    /// Server Version successfuly arrived, do a first PING
    ServerVersionArrived(ServerInfo),
    /// We're currently authenticating with the server
    Authentication,
    /// Loading map data, site information, recipe information and other
    /// initialization data
    LoadingInitData,
    /// Prepare data received by the server to be used by the client (insert
    /// data into the ECS, render map)
    StartingClient,
    /// Requesting Plugins from Server and downloading them
    RequestingPlugins,
}

/// Use this to get the "token_or_username" which is required by a server, token
/// if auth is used, username if it runs without auth.
/// NOTE: only call it if you trust the auth_provider!
pub(crate) async fn resolve_token_or_username(
    credentials: Credentials,
    trusted_auth_provider: &Option<String>,
) -> Result<String, Error> {
    match credentials {
        Credentials::Username(username) => Ok(username),
        Credentials::UsernamePassword(username, password) => match &trusted_auth_provider {
            Some(addr) => {
                let (scheme, authority) = match addr.split_once("://") {
                    Some((s, a)) => (s, a),
                    None => return Err(Error::AuthServerUrlInvalid(addr.to_string())),
                };

                let scheme = match scheme.parse::<authc::Scheme>() {
                    Ok(s) => s,
                    Err(_) => return Err(Error::AuthServerUrlInvalid(addr.to_string())),
                };

                let authority = match authority.parse::<authc::Authority>() {
                    Ok(a) => a,
                    Err(_) => return Err(Error::AuthServerUrlInvalid(addr.to_string())),
                };

                Ok(authc::AuthClient::new(scheme, authority)?
                    .sign_in(username, password)
                    .await?
                    .serialize())
            },
            None => Ok(username),
        },
    }
}

/// Path of the realm-bridge executable (same variable as the server).
const ENV_BRIDGE: &str = "VELOREN_REALM_BRIDGE";
/// Realm connection file (REALM_URL / REALM_CANISTER / REALM_LOCAL).
const ENV_REALM: &str = "VELOREN_REALM_ENV";
/// The player's key (PEM). Unset: a dev identity derived from the username.
const ENV_IDENTITY: &str = "VELOREN_REALM_IDENTITY";

/// The auth provider of a server whose logins go through the realm canister,
/// as advertised by `ic_auth_provider`: `ic:<world>:<host principal hex>`.
/// Such servers ask for a username only; no password leaves this machine.
pub(crate) fn ic_provider(auth_provider: &Option<String>) -> Option<&str> {
    auth_provider.as_deref().filter(|p| p.starts_with("ic:"))
}

/// Internet Computer login (Phase 3): sign as the player with `realm-bridge`,
/// call `join_world` (lets this server's host act for us in its world and
/// registers a one-time nonce) and return the `ic:<nonce>:<name>` token the
/// server redeems.
pub(crate) async fn resolve_ic_login(credentials: Credentials, provider: &str) -> Result<String, Error> {
    let name = match credentials {
        Credentials::Username(name) | Credentials::UsernamePassword(name, _) => name,
    };
    let (world, host) = ic::parse_ic_auth_provider(provider)
        .ok_or_else(|| Error::AuthServerUrlInvalid(provider.to_owned()))?;
    let provider = provider.to_owned();
    tokio::task::spawn_blocking(move || ic_login_blocking(world, host, name, &provider))
        .await
        .map_err(|e| Error::AuthErr(format!("IC login task failed: {e}")))?
}

fn ic_login_blocking(
    world: ic::WorldId,
    host: ic::PrincipalBytes,
    name: String,
    provider: &str,
) -> Result<String, Error> {
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    let var = |key: &str| {
        std::env::var(key).map_err(|_| {
            Error::AuthErr(format!(
                "This server logs in with the Internet Computer ({provider}); set {ENV_BRIDGE} \
                 and {ENV_REALM} (make veloren-client does this)"
            ))
        })
    };
    let program = var(ENV_BRIDGE)?;
    let realm = var(ENV_REALM)?;
    let mut command = Command::new(&program);
    command.args(["--env", &realm, "--name", "client-login"]);
    match std::env::var(ENV_IDENTITY) {
        Ok(pem) if !pem.is_empty() => {
            command.args(["--identity", &pem]);
        },
        _ => {
            warn!(
                %name,
                "IC login with a dev identity derived from the username: anyone can \
                 impersonate it. Development only (set {ENV_IDENTITY} to a key)."
            );
            command.args(["--dev-identity", &name]);
        },
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Error::AuthErr(format!("cannot start {program}: {e}")))?;
    let request = serde_json::json!({
        "id": 1,
        "method": "login",
        "args": { "world": world, "host": host, "name": name },
    });
    let reply = (|| -> std::io::Result<String> {
        let mut stdin = child.stdin.take().expect("piped stdin");
        writeln!(stdin, "{request}")?;
        stdin.flush()?;
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("piped stdout")).read_line(&mut line)?;
        Ok(line)
    })();
    let _ = child.kill();
    let _ = child.wait();
    let reply = reply.map_err(|e| Error::AuthErr(format!("realm-bridge: {e}")))?;
    let reply: serde_json::Value = serde_json::from_str(&reply).map_err(|e| {
        Error::AuthErr(format!("realm-bridge gave no answer ({e}); see its log lines above"))
    })?;
    if let Some(err) = reply.get("error") {
        return Err(Error::AuthErr(format!("IC login failed: {err}")));
    }
    let token = reply["ok"]["token"]
        .as_str()
        .ok_or_else(|| Error::AuthErr(format!("IC login: unexpected reply {reply}")))?;
    info!(%name, world = world.0, "joined the world on the Internet Computer");
    Ok(token.to_owned())
}

pub(crate) async fn connect_quic(
    network: &Network,
    hostname: String,
    override_port: Option<u16>,
    prefer_ipv6: bool,
    validate_tls: bool,
) -> Result<network::Participant, crate::error::Error> {
    let config = if validate_tls {
        quinn::ClientConfig::try_with_platform_verifier()?
    } else {
        warn!(
            "skipping validation of server identity. There is no guarantee that the server you're \
             connected to is the one you expect to be connecting to."
        );
        #[derive(Debug)]
        struct Verifier;
        impl rustls::client::danger::ServerCertVerifier for Verifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA1,
                    rustls::SignatureScheme::ECDSA_SHA1_Legacy,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ED448,
                ]
            }
        }

        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Verifier))
            .with_no_client_auth();
        cfg.enable_early_data = true;

        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(cfg).unwrap(),
        ))
    };

    addr::try_connect(network, &hostname, override_port, prefer_ipv6, |a| {
        ConnectAddr::Quic(a, config.clone(), hostname.clone())
    })
    .await
}
