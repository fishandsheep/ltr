//! Local web console for managing tunnels.

use std::{future::Future, net::SocketAddr};

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
pub use ltr_relay::OnReady;
use serde_json::json;
use tokio::{net::TcpListener, sync::oneshot};

/// Callback fired with the bound console address once a web mode finishes
/// startup.
pub type OnReadyAddr = Box<dyn FnOnce(SocketAddr) + Send>;

/// HTTP API routes and handlers.
pub mod api;
/// Persistent Web credentials.
pub mod credentials;
mod probe;
pub(crate) mod registry;
mod runtime;
mod session;
/// In-memory state and tunnel metadata.
pub mod state;
pub mod tunnel;

pub use state::{
    default_tunnels_path, SessionInfo, SessionMode, StateError, SystemTunnelRole, SystemTunnelSpec,
    TunnelConfig, TunnelInfo, TunnelKind, TunnelStatus, WebLimits, WebState, WebTlsConfig,
};

const INDEX_HTML: &str = include_str!("static/index.html");
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const STYLE_CSS: &str = include_str!("static/style.css");

/// Embedded static asset: request path under `/js/` and MIME type.
struct JsAsset {
    path: &'static str,
    content_type: &'static str,
    body: &'static str,
}

const JS_ASSETS: &[JsAsset] = &[
    asset("app.mjs", include_str!("static/js/app.mjs")),
    asset("lib.mjs", include_str!("static/js/lib.mjs")),
    asset("i18n.mjs", include_str!("static/js/i18n.mjs")),
    asset("api.mjs", include_str!("static/js/api.mjs")),
    asset(
        "vendor/preact.mjs",
        include_str!("static/js/vendor/preact.mjs"),
    ),
    asset(
        "vendor/hooks.mjs",
        include_str!("static/js/vendor/hooks.mjs"),
    ),
    asset("vendor/htm.mjs", include_str!("static/js/vendor/htm.mjs")),
    asset(
        "components/App.mjs",
        include_str!("static/js/components/App.mjs"),
    ),
    asset(
        "components/AuthPanel.mjs",
        include_str!("static/js/components/AuthPanel.mjs"),
    ),
    asset(
        "components/ConfirmDialog.mjs",
        include_str!("static/js/components/ConfirmDialog.mjs"),
    ),
    asset(
        "components/Topology.mjs",
        include_str!("static/js/components/Topology.mjs"),
    ),
    asset(
        "components/TunnelCard.mjs",
        include_str!("static/js/components/TunnelCard.mjs"),
    ),
    asset(
        "components/TunnelDialog.mjs",
        include_str!("static/js/components/TunnelDialog.mjs"),
    ),
];

const fn asset(path: &'static str, body: &'static str) -> JsAsset {
    JsAsset {
        path,
        content_type: "application/javascript; charset=utf-8",
        body,
    }
}

/// Web HTTP server config.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Local address to bind HTTP server to.
    pub addr: SocketAddr,
    /// Session metadata exposed through `/api/session`.
    pub session: SessionInfo,
}

enum BoundWebListener {
    Http {
        listener: TcpListener,
        addr: SocketAddr,
    },
    Https {
        listener: std::net::TcpListener,
        addr: SocketAddr,
        config: RustlsConfig,
    },
}

impl BoundWebListener {
    fn addr(&self) -> SocketAddr {
        match self {
            Self::Http { addr, .. } | Self::Https { addr, .. } => *addr,
        }
    }

    fn scheme(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Https { .. } => "https",
        }
    }
}

/// Starts local web console server.
pub async fn serve(config: ServeConfig) -> Result<()> {
    let state = WebState::new(config.session.clone());
    serve_with_state(config, state, tokio::signal::ctrl_c()).await
}

/// Starts web console server with provided state and shutdown signal.
pub async fn serve_with_state<S>(config: ServeConfig, state: WebState, shutdown: S) -> Result<()>
where
    S: Future<Output = std::result::Result<(), std::io::Error>> + Send + 'static,
{
    serve_with_state_on_ready(config, state, shutdown, None).await
}

/// Serves the web console on `config.addr` until `shutdown` resolves. The
/// callback fires once the listener is bound, receiving the bound address.
pub async fn serve_with_state_on_ready<S>(
    config: ServeConfig,
    state: WebState,
    shutdown: S,
    on_ready: Option<OnReadyAddr>,
) -> Result<()>
where
    S: Future<Output = std::result::Result<(), std::io::Error>> + Send + 'static,
{
    validate_web_bind(config.addr, &state)?;
    let bound = bind_web_listener(config.addr, state.web_tls()).await?;
    if let Some(on_ready) = on_ready {
        on_ready(bound.addr());
    }
    serve_bound(bound, state, async move {
        let _ = shutdown.await;
    })
    .await
}

async fn bind_web_listener(
    addr: SocketAddr,
    tls: Option<WebTlsConfig>,
) -> Result<BoundWebListener> {
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            let addr = listener.local_addr()?;
            let bound = into_bound_listener(listener, addr, tls).await?;
            println!("LTR web console listening on {}://{addr}", bound.scheme());
            Ok(bound)
        }
        Err(primary_err) if addr.port() != 0 => {
            let fallback_addr = SocketAddr::new(addr.ip(), 0);
            match TcpListener::bind(fallback_addr).await {
                Ok(listener) => {
                    let actual_addr = listener.local_addr()?;
                    eprintln!("Failed to bind web console on {addr}: {primary_err}");
                    let bound = into_bound_listener(listener, actual_addr, tls).await?;
                    println!(
                        "LTR web console switched to {}://{actual_addr}",
                        bound.scheme()
                    );
                    Ok(bound)
                }
                Err(fallback_err) => Err(anyhow!(
                    "failed to bind web console on {addr}: {primary_err}; also failed to bind an available port on {}: {fallback_err}. Try --web-addr 127.0.0.1:9000",
                    addr.ip()
                )),
            }
        }
        Err(err) => Err(anyhow!("failed to bind web console on {addr}: {err}")),
    }
}

async fn into_bound_listener(
    listener: TcpListener,
    addr: SocketAddr,
    tls: Option<WebTlsConfig>,
) -> Result<BoundWebListener> {
    match tls {
        Some(tls) => {
            let listener = listener.into_std()?;
            let config = RustlsConfig::from_pem(tls.cert_pem, tls.key_pem).await?;
            Ok(BoundWebListener::Https {
                listener,
                addr,
                config,
            })
        }
        None => Ok(BoundWebListener::Http { listener, addr }),
    }
}

async fn serve_bound<S>(bound: BoundWebListener, state: WebState, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    match bound {
        BoundWebListener::Http { listener, .. } => {
            axum::serve(listener, router(state))
                .with_graceful_shutdown(async move {
                    shutdown.await;
                })
                .await?;
        }
        BoundWebListener::Https {
            listener, config, ..
        } => {
            let handle = Handle::new();
            let server = axum_server::from_tcp_rustls(listener, config)?.handle(handle.clone());
            let mut server_task = tokio::spawn(server.serve(router(state).into_make_service()));
            tokio::pin!(shutdown);
            tokio::select! {
                result = &mut server_task => {
                    result??;
                }
                _ = &mut shutdown => {
                    handle.graceful_shutdown(None);
                    server_task.await??;
                }
            }
        }
    }
    Ok(())
}

/// Runs web console plus required system tunnels.
pub async fn run_managed<S>(
    config: ServeConfig,
    state: WebState,
    system_tunnels: Vec<SystemTunnelSpec>,
    shutdown: S,
) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    run_managed_on_ready(config, state, system_tunnels, shutdown, None).await
}

/// Like [`run_managed`], with a callback fired once the console listener is
/// bound and all system tunnels are running.
pub async fn run_managed_on_ready<S>(
    config: ServeConfig,
    state: WebState,
    system_tunnels: Vec<SystemTunnelSpec>,
    shutdown: S,
    on_ready: Option<OnReadyAddr>,
) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    validate_web_bind(config.addr, &state)?;
    let bound = bind_web_listener(config.addr, state.web_tls()).await?;
    let web_port = bound.addr().port();
    let mut system_ids = Vec::with_capacity(system_tunnels.len());
    for mut spec in system_tunnels {
        if spec.role == SystemTunnelRole::WebConsole {
            spec.config.local_port = web_port;
        }
        let id = state
            .ensure_system_tunnel(spec)
            .await
            .map_err(|err| anyhow!(err.message))?;
        state
            .start_tunnel(&id)
            .await
            .map_err(|err| anyhow!(err.message))?;
        system_ids.push(id);
    }

    for id in &system_ids {
        state
            .wait_for_running(id)
            .await
            .map_err(|err| anyhow!(err.message))?;
    }

    if let Some(url) = state.session().await.web_remote_url {
        println!("Remote web console: {url}");
    }
    if let Some(endpoint) = state.session().await.ssh_remote_endpoint {
        println!("Remote SSH tunnel: {endpoint}");
    }

    let (serve_shutdown_tx, serve_shutdown_rx) = oneshot::channel::<()>();
    let mut serve_task = tokio::spawn(serve_bound(bound, state.clone(), async move {
        let _ = serve_shutdown_rx.await;
    }));
    let monitor_state = state.clone();
    let monitor_ids = system_ids.clone();
    let mut monitor_task =
        tokio::spawn(async move { monitor_state.monitor_locked_tunnels(&monitor_ids).await });

    if let Some(on_ready) = on_ready {
        on_ready(SocketAddr::new(config.addr.ip(), web_port));
    }

    tokio::pin!(shutdown);

    let mut server_finished = false;
    let result = tokio::select! {
        _ = &mut shutdown => Ok(()),
        server = &mut serve_task => {
            server_finished = true;
            match server {
                Ok(result) => result,
                Err(err) => Err(anyhow!(err)),
            }
        },
        monitor = &mut monitor_task => match monitor {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(anyhow!(err.message)),
            Err(err) => Err(anyhow!(err)),
        },
    };

    let _ = serve_shutdown_tx.send(());
    state.shutdown_all().await;
    if !server_finished {
        let _ = serve_task.await;
    }
    monitor_task.abort();
    result
}

fn validate_web_bind(addr: SocketAddr, state: &WebState) -> Result<()> {
    if !addr.ip().is_loopback() && !state.web_auth_enabled() {
        return Err(anyhow!(
            "Web console cannot bind to a non-loopback address without bearer-token authentication"
        ));
    }
    Ok(())
}

/// Builds web console router.
pub fn router(state: WebState) -> Router {
    let api = api::router().layer(middleware::from_fn_with_state(state.clone(), authorize_api));

    Router::new()
        .route("/", get(index))
        .route("/style.css", get(style_css))
        .route("/js/*path", get(js_asset))
        .nest("/api", api)
        .with_state(state)
}

async fn authorize_api(State(state): State<WebState>, request: Request, next: Next) -> Response {
    if !state.web_auth_enabled() {
        // Without a token, loopback is the only access control: refuse requests
        // whose Host or Origin names another site (DNS rebinding, cross-site).
        if !local_request_allowed(request.headers(), request.uri()) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "request must target a loopback host" })),
            )
                .into_response();
        }
        return next.run(request).await;
    }

    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if token.is_some_and(|token| state.web_token_matches(token)) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({ "error": "missing or invalid Web bearer token" })),
        )
            .into_response()
    }
}

/// True when the `Host` and `Origin` headers, if present, name a loopback host.
fn local_request_allowed(headers: &HeaderMap, uri: &axum::http::Uri) -> bool {
    let uri_authority_ok = uri
        .authority()
        .is_none_or(|authority| is_loopback_authority(authority.as_str()));
    let hosts = headers.get_all(header::HOST);
    let mut hosts = hosts.iter();
    let host_ok = hosts
        .next()
        .is_none_or(|value| value.to_str().is_ok_and(is_loopback_authority))
        && hosts.next().is_none();

    let origins = headers.get_all(header::ORIGIN);
    let mut origins = origins.iter();
    let origin_ok = origins.next().is_none_or(|value| {
        value.to_str().ok().is_some_and(|origin| {
            origin.parse::<axum::http::Uri>().is_ok_and(|uri| {
                matches!(uri.scheme_str(), Some("http" | "https"))
                    && uri
                        .authority()
                        .is_some_and(|authority| is_loopback_authority(authority.as_str()))
            })
        })
    }) && origins.next().is_none();

    uri_authority_ok && host_ok && origin_ok
}

/// Checks a parsed host against the loopback names.
fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Parses `Host` as an HTTP authority and accepts only loopback hosts.
fn is_loopback_authority(authority: &str) -> bool {
    authority
        .parse::<axum::http::uri::Authority>()
        .is_ok_and(|authority| {
            !authority.as_str().contains('@') && is_loopback_host(authority.host())
        })
}

async fn index() -> impl IntoResponse {
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (
                axum::http::header::CONTENT_SECURITY_POLICY,
                CONTENT_SECURITY_POLICY,
            ),
        ],
        Html(INDEX_HTML),
    )
}

/// Strong ETag for an embedded asset body. Assets change only when the
/// binary changes, so a content hash is stable per build.
fn asset_etag(body: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("\"{}\"", hex::encode(Sha256::digest(body.as_bytes())))
}

fn serve_asset(headers: &HeaderMap, content_type: &str, body: &'static str) -> Response {
    let etag = asset_etag(body);
    let revalidated = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|if_none_match| {
            if_none_match
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == etag || candidate == "*")
        });
    if revalidated {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (axum::http::header::ETAG, etag.as_str()),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
        )
            .into_response();
    }
    (
        [
            (axum::http::header::CONTENT_TYPE, content_type),
            (axum::http::header::ETAG, etag.as_str()),
            // Stable URLs across builds: browsers must revalidate instead of
            // serving stale assets after an upgrade.
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

async fn js_asset(headers: HeaderMap, Path(path): Path<String>) -> Response {
    match JS_ASSETS.iter().find(|asset| asset.path == path) {
        Some(asset) => serve_asset(&headers, asset.content_type, asset.body),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn style_css(headers: HeaderMap) -> Response {
    serve_asset(&headers, "text/css; charset=utf-8", STYLE_CSS)
}

#[cfg(test)]
mod tests {
    use super::{bind_web_listener, state::WebTlsConfig, validate_web_bind, BoundWebListener};
    use crate::web::{SessionInfo, WebState};
    use rcgen::generate_simple_self_signed;
    use tokio::net::TcpListener;

    #[test]
    fn non_loopback_web_bind_requires_authentication() {
        let state = WebState::default();
        let addr = "0.0.0.0:7836".parse().unwrap();
        assert!(validate_web_bind(addr, &state).is_err());

        let authenticated = WebState::with_web_token(SessionInfo::local(), Some("token".into()));
        assert!(validate_web_bind(addr, &authenticated).is_ok());
        assert!(validate_web_bind("127.0.0.1:7836".parse().unwrap(), &state).is_ok());
    }

    #[tokio::test]
    async fn bind_web_listener_falls_back_when_requested_port_is_busy() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied.local_addr().unwrap();

        let bound = bind_web_listener(occupied_addr, None).await.unwrap();

        assert_eq!(bound.addr().ip(), occupied_addr.ip());
        assert_ne!(bound.addr().port(), occupied_addr.port());
        assert_ne!(bound.addr().port(), 0);
    }

    #[tokio::test]
    async fn bind_web_listener_accepts_pem_tls() {
        let certificate = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let tls = WebTlsConfig {
            cert_pem: certificate.cert.pem().into_bytes(),
            key_pem: certificate.signing_key.serialize_pem().into_bytes(),
        };

        let bound = bind_web_listener("127.0.0.1:0".parse().unwrap(), Some(tls))
            .await
            .unwrap();
        assert!(matches!(bound, BoundWebListener::Https { .. }));
    }
}
