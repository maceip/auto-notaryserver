use axum::{
    extract::Request,
    http::StatusCode,
    middleware::from_extractor_with_state,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use hyper::{body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use notify::{
    event::ModifyKind, Error, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use rustls::ServerConfig;
use std::{
    collections::HashMap,
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::{fs::File, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use tower_http::cors::CorsLayer;
use tower_service::Service;
use tracing::{debug, error, info};

use crate::{
    config::{NotaryServerProperties, NotarySigningKeyProperties},
    domain::{
        auth::{authorization_whitelist_vec_into_hashmap, AuthorizationWhitelistRecord},
        notary::NotaryGlobals,
        InfoResponse,
    },
    error::NotaryServerError,
    middleware::AuthorizationMiddleware,
    service::{initialize, upgrade_protocol},
    util::parse_csv_file,
};
use clap::Parser;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio_rustls_acme::caches::DirCache;
use tokio_rustls_acme::{AcmeAcceptor, AcmeConfig};
use tokio_stream::StreamExt;

/// Start a TCP server (with or without TLS) to accept notarization request for both TCP and WebSocket clients
#[tracing::instrument(skip(config))]
pub async fn run_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {

    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    let notary_signing_key = load_notary_signing_key(&config.notary_key).await?;

    // Load the private key for notarized transcript signing

    // Load the authorization whitelist csv if it is turned on
    let authorization_whitelist =
        load_authorization_whitelist(config)?.map(|whitelist| Arc::new(Mutex::new(whitelist)));
    // Enable hot reload if authorization whitelist is available
    let watcher =
        watch_and_reload_authorization_whitelist(config.clone(), authorization_whitelist.clone())?;
    if watcher.is_some() {
        debug!("Successfully setup watcher for hot reload of authorization whitelist!");
    }

    let notary_address = SocketAddr::new(
        IpAddr::V4(config.server.host.parse().map_err(|err| {
            eyre!("Failed to parse notary host address from server config: {err}")
        })?),
        config.server.port,
    );
    let mut listener = TcpListener::bind(notary_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;

    info!("Listening for TCP traffic at {}", notary_address);

    let protocol = Arc::new(http1::Builder::new());
    let notary_globals = NotaryGlobals::new(
        notary_signing_key,
        config.notarization.clone(),
        authorization_whitelist,
    );

    // Parameters needed for the info endpoint
    let public_key = std::fs::read_to_string(&config.notary_key.public_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary public signing key for notarization: {err}"))?;
    let version = env!("CARGO_PKG_VERSION").to_string();
    let git_commit_hash = env!("GIT_COMMIT_HASH").to_string();
    let git_commit_timestamp = env!("GIT_COMMIT_TIMESTAMP").to_string();

    // Parameters needed for the root / endpoint
    let html_string = config.server.html_info.clone();
    let html_info = Html(
        html_string
            .replace("{version}", &version)
            .replace("{git_commit_hash}", &git_commit_hash)
            .replace("{git_commit_timestamp}", &git_commit_timestamp)
            .replace("{public_key}", &public_key),
    );
    let router: Router = Router::new()
        .route(
            "/",
            get(|| async move { (StatusCode::OK, html_info).into_response() }),
        )
        .route(
            "/healthcheck",
            get(|| async move { (StatusCode::OK, "Ok").into_response() }),
        )
        .route(
            "/info",
            get(|| async move {
                (
                    StatusCode::OK,
                    Json(InfoResponse {
                        version,
                        public_key,
                        git_commit_hash,
                        git_commit_timestamp,
                    }),
                )
                    .into_response()
            }),
        )
        .route("/session", post(initialize))
        // Not applying auth middleware to /notarize endpoint for now as we can rely on our
        // short-lived session id generated from /session endpoint, as it is not possible
        // to use header for API key for websocket /notarize endpoint due to browser restriction
        // ref: https://stackoverflow.com/a/4361358; And putting it in url query param
        // seems to be more insecured: https://stackoverflow.com/questions/5517281/place-api-key-in-headers-or-url
        .route_layer(from_extractor_with_state::<
            AuthorizationMiddleware,
            NotaryGlobals,
        >(notary_globals.clone()))
        .route("/notarize", get(upgrade_protocol))
        .layer(CorsLayer::permissive())
        .with_state(notary_globals);

    let mut state = AcmeConfig::new([&config.domain])
        .contact([&config.email].iter().map(|e| format!("mailto:{}", e)))
        .cache_option(Some(DirCache::new(".")))
        .directory_lets_encrypt(true)
        .state();
    let rustls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());

    let acceptor = state.acceptor();

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    });

    serve(acceptor, Arc::new(rustls_config),  config.server.port).await;

    Ok(())
}

async fn serve(acceptor: AcmeAcceptor, rustls_config: Arc<ServerConfig>, port: u16) {
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port))
        .await
        .unwrap();
    loop {
        let tcp = listener.accept().await.unwrap().0;
        let rustls_config = rustls_config.clone();
        let accept_future = acceptor.accept(tcp);

        tokio::spawn(async move {
            match accept_future.await.unwrap() {
                None => log::info!("received TLS-ALPN-01 validation request"),
                Some(start_handshake) => {
                    let mut tls = start_handshake.into_stream(rustls_config).await.unwrap();
                    //tls.write_all(HELLO).await.unwrap();
                    tls.shutdown().await.unwrap();
                }
            }
        });
    }
}

/// Load notary signing key from static file
async fn load_notary_signing_key(config: &NotarySigningKeyProperties) -> Result<SigningKey> {
    debug!("Loading notary server's signing key");

    let notary_signing_key = SigningKey::read_pkcs8_pem_file(&config.private_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary signing key for notarization: {err}"))?;

    debug!("Successfully loaded notary server's signing key!");
    Ok(notary_signing_key)
}

/// Read a PEM-formatted file and return its buffer reader
pub async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

/// Load notary tls private key and cert from static files
/// Load authorization whitelist if it is enabled
fn load_authorization_whitelist(
    config: &NotaryServerProperties,
) -> Result<Option<HashMap<String, AuthorizationWhitelistRecord>>> {
    let authorization_whitelist = if !config.authorization.enabled {
        debug!("Skipping authorization as it is turned off.");
        None
    } else {
        // Load the csv
        let whitelist_csv = parse_csv_file::<AuthorizationWhitelistRecord>(
            &config.authorization.whitelist_csv_path,
        )
        .map_err(|err| eyre!("Failed to parse authorization whitelist csv: {:?}", err))?;
        // Convert the whitelist record into hashmap for faster lookup
        let whitelist_hashmap = authorization_whitelist_vec_into_hashmap(whitelist_csv);
        Some(whitelist_hashmap)
    };
    Ok(authorization_whitelist)
}

// Setup a watcher to detect any changes to authorization whitelist
// When the list file is modified, the watcher thread will reload the whitelist
// The watcher is setup in a separate thread by the notify library which is synchronous
fn watch_and_reload_authorization_whitelist(
    config: NotaryServerProperties,
    authorization_whitelist: Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>>,
) -> Result<Option<RecommendedWatcher>> {
    // Only setup the watcher if auth whitelist is loaded
    let watcher = if let Some(authorization_whitelist) = authorization_whitelist {
        let cloned_config = config.clone();
        // Setup watcher by giving it a function that will be triggered when an event is detected
        let mut watcher = RecommendedWatcher::new(
            move |event: Result<Event, Error>| {
                match event {
                    Ok(event) => {
                        // Only reload whitelist if it's an event that modified the file data
                        if let EventKind::Modify(ModifyKind::Data(_)) = event.kind {
                            debug!("Authorization whitelist is modified");
                            match load_authorization_whitelist(&cloned_config) {
                                Ok(Some(new_authorization_whitelist)) => {
                                    *authorization_whitelist.lock().unwrap() = new_authorization_whitelist;
                                    info!("Successfully reloaded authorization whitelist!");
                                }
                                Ok(None) => unreachable!(
                                    "Authorization whitelist will never be None as the auth module is enabled"
                                ),
                                // Ensure that error from reloading doesn't bring the server down
                                Err(err) => error!("{err}"),
                            }
                        }
                    },
                    Err(err) => {
                        error!("Error occured when watcher detected an event: {err}")
                    }
                }
            },
            notify::Config::default(),
        )
        .map_err(|err| eyre!("Error occured when setting up watcher for hot reload: {err}"))?;

        // Start watcher to listen to any changes on the whitelist file
        watcher
            .watch(
                Path::new(&config.authorization.whitelist_csv_path),
                RecursiveMode::Recursive,
            )
            .map_err(|err| eyre!("Error occured when starting up watcher for hot reload: {err}"))?;

        Some(watcher)
    } else {
        // Skip setup the watcher if auth whitelist is not loaded
        None
    };
    // Need to return the watcher to parent function, else it will be dropped and stop listening
    Ok(watcher)
}
