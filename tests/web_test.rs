use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use ltr_cli::{
    server::Server,
    shared::CONTROL_PORT,
    web::{
        router, run_managed, ServeConfig, SessionInfo, SessionMode, SystemTunnelRole,
        SystemTunnelSpec, TunnelConfig, WebLimits, WebState,
    },
};
use serde_json::{json, Value};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex},
    task::JoinHandle,
    time,
};
use tower::ServiceExt;

static SERIAL_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct ServerGuard {
    task: JoinHandle<Result<()>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn wait_for_control_port_closed() -> Result<()> {
    for _ in 0..100 {
        if TcpStream::connect(("localhost", CONTROL_PORT))
            .await
            .is_err()
        {
            return Ok(());
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    Err(anyhow!("previous server did not release control port"))
}

async fn spawn_server(secret: Option<&str>) -> Result<ServerGuard> {
    wait_for_control_port_closed().await?;
    let task = tokio::spawn(Server::new(1024..=65535, secret).listen());

    for _ in 0..250 {
        if task.is_finished() {
            return match task.await {
                Ok(Ok(())) => Err(anyhow!("server exited before listening")),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            };
        }

        match TcpStream::connect(("localhost", CONTROL_PORT)).await {
            Ok(_) => return Ok(ServerGuard { task }),
            Err(_) => time::sleep(Duration::from_millis(10)).await,
        }
    }

    Err(anyhow!("server did not start listening on control port"))
}

async fn json_response(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    serde_json::from_slice(&bytes).expect("body should be JSON")
}

fn remote_session(mode: SessionMode) -> SessionInfo {
    SessionInfo {
        mode,
        warnings: vec!["warning".to_string()],
        loopback_only: true,
        web_remote_url: Some("https://localhost:7836".to_string()),
        ssh_remote_endpoint: if mode == SessionMode::Home {
            Some("localhost:2222".to_string())
        } else {
            None
        },
    }
}

fn tunnel_config(name: &str) -> TunnelConfig {
    TunnelConfig {
        name: name.to_string(),
        local_port: 3000,
        to: "localhost".to_string(),
        port: None,
        local_host: "127.0.0.1".to_string(),
        secret: None,
    }
}

async fn wait_for_condition(mut check: impl FnMut() -> bool) -> Result<()> {
    for _ in 0..250 {
        if check() {
            return Ok(());
        }
        time::sleep(Duration::from_millis(20)).await;
    }
    Err(anyhow!("condition not met before timeout"))
}

#[tokio::test]
async fn get_session_returns_remote_metadata() {
    let state = WebState::new(remote_session(SessionMode::RemoteWeb));
    let app = router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    assert_eq!(body["mode"], "RemoteWeb");
    assert_eq!(body["loopback_only"], true);
    assert_eq!(body["web_remote_url"], "https://localhost:7836");
}

#[tokio::test]
async fn remote_api_requires_bearer_token() {
    let state = WebState::with_web_token(
        remote_session(SessionMode::RemoteWeb),
        Some("web-secret".to_string()),
    );
    let app = router(state);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request should succeed");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let wrong_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request should succeed");
    assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header("authorization", "Bearer web-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request should succeed");
    assert_eq!(authorized.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_tunnels_returns_empty_array() {
    let app = router(WebState::default());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/tunnels")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    assert_eq!(body, json!([]));
}

#[tokio::test]
async fn web_state_rejects_tunnels_over_configured_limit() -> Result<()> {
    let state = WebState::with_limits(
        SessionInfo::local(),
        None,
        None,
        WebLimits {
            max_tunnels: 1,
            max_active_connections: 1,
            max_log_lines: 2,
        },
    );
    state.create_tunnel(tunnel_config("one")).await?;
    let error = state
        .create_tunnel(TunnelConfig {
            name: "two".to_string(),
            local_port: 3001,
            ..tunnel_config("two")
        })
        .await
        .unwrap_err();
    assert!(error.message.contains("tunnel limit reached"));
    Ok(())
}

#[tokio::test]
async fn remote_mode_rejects_non_loopback_local_host() {
    let app = router(WebState::new(remote_session(SessionMode::RemoteWeb)));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tunnels")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "dev",
                        "local_port": 3000,
                        "to": "localhost",
                        "port": null,
                        "local_host": "192.168.1.10",
                        "secret": null
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn locked_system_tunnel_actions_return_conflict() -> Result<()> {
    let state = WebState::new(remote_session(SessionMode::Home));
    let id = state
        .create_system_tunnel(SystemTunnelSpec {
            role: SystemTunnelRole::WebConsole,
            config: TunnelConfig {
                port: Some(7836),
                ..tunnel_config("Web Console")
            },
            display_url: Some("https://localhost:7836".to_string()),
        })
        .await?;
    let app = router(state);

    for (method, uri) in [
        ("PUT", format!("/api/tunnels/{id}")),
        ("DELETE", format!("/api/tunnels/{id}")),
        ("POST", format!("/api/tunnels/{id}/stop")),
    ] {
        let builder = Request::builder().method(method).uri(uri);
        let request = if method == "PUT" {
            builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&tunnel_config("other"))?))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let response = app.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    Ok(())
}

#[tokio::test]
async fn tunnel_crud_and_logs_api() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    let _server = spawn_server(None).await?;
    let app = router(WebState::default());

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tunnels")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&tunnel_config("dev"))?))
                .unwrap(),
        )
        .await?;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body = json_response(create_response).await;
    let id = create_body["id"]
        .as_str()
        .expect("id should exist")
        .to_string();

    let start_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/tunnels/{id}/start"))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(start_response.status(), StatusCode::OK);

    let mut list_body = json!([]);
    wait_for_condition(|| false).await.err();
    for _ in 0..250 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tunnels")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        list_body = json_response(response).await;
        if list_body[0]["status"] == "Running" {
            break;
        }
        time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(list_body[0]["status"], "Running");
    assert_eq!(list_body[0]["kind"], "User");
    assert_eq!(list_body[0]["locked"], false);

    let logs_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/tunnels/{id}/logs"))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(logs_response.status(), StatusCode::OK);
    let logs_body = json_response(logs_response).await;
    assert!(logs_body["logs"].as_array().expect("logs array").len() >= 2);

    let stop_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/tunnels/{id}/stop"))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(stop_response.status(), StatusCode::OK);

    let delete_response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/tunnels/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(delete_response.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn managed_remote_web_starts_and_stops_system_tunnel() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    let _server = spawn_server(None).await?;
    let state = WebState::new(remote_session(SessionMode::RemoteWeb));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(run_managed(
        ServeConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            session: state.session().await,
        },
        state.clone(),
        vec![SystemTunnelSpec {
            role: SystemTunnelRole::WebConsole,
            config: TunnelConfig {
                name: "Web Console".to_string(),
                local_port: 9,
                to: "localhost".to_string(),
                port: Some(7836),
                local_host: "127.0.0.1".to_string(),
                secret: None,
            },
            display_url: Some("https://localhost:7836".to_string()),
        }],
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    for _ in 0..250 {
        let tunnels = state.list_tunnels().await;
        if tunnels.len() == 1 && tunnels[0].status == ltr_cli::web::TunnelStatus::Running {
            assert_eq!(tunnels[0].kind, ltr_cli::web::TunnelKind::System);
            assert!(tunnels[0].remote_port.is_some());
            break;
        }
        time::sleep(Duration::from_millis(20)).await;
    }

    let session = state.session().await;
    assert_eq!(
        session.web_remote_url.as_deref(),
        Some("https://localhost:7836")
    );

    let _ = shutdown_tx.send(());
    task.await??;

    let tunnels = state.list_tunnels().await;
    assert_eq!(tunnels[0].status, ltr_cli::web::TunnelStatus::Stopped);
    Ok(())
}

#[tokio::test]
async fn managed_remote_web_uses_fallback_web_port_for_system_tunnel() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    let _server = spawn_server(None).await?;
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let occupied_addr = occupied.local_addr()?;
    let state = WebState::new(remote_session(SessionMode::RemoteWeb));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(run_managed(
        ServeConfig {
            addr: occupied_addr,
            session: state.session().await,
        },
        state.clone(),
        vec![SystemTunnelSpec {
            role: SystemTunnelRole::WebConsole,
            config: TunnelConfig {
                name: "Web Console".to_string(),
                local_port: occupied_addr.port(),
                to: "localhost".to_string(),
                port: Some(7836),
                local_host: "127.0.0.1".to_string(),
                secret: None,
            },
            display_url: Some("https://localhost:7836".to_string()),
        }],
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut saw_running = false;
    for _ in 0..250 {
        let tunnels = state.list_tunnels().await;
        if tunnels.len() == 1 && tunnels[0].status == ltr_cli::web::TunnelStatus::Running {
            assert_ne!(tunnels[0].config.local_port, occupied_addr.port());
            assert_ne!(tunnels[0].config.local_port, 0);
            saw_running = true;
            break;
        }
        time::sleep(Duration::from_millis(20)).await;
    }
    assert!(saw_running, "system tunnel should start on fallback port");

    let _ = shutdown_tx.send(());
    task.await??;
    Ok(())
}

#[tokio::test]
async fn managed_home_starts_two_locked_system_tunnels() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    let _server = spawn_server(None).await?;
    let state = WebState::new(remote_session(SessionMode::Home));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(run_managed(
        ServeConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            session: state.session().await,
        },
        state.clone(),
        vec![
            SystemTunnelSpec {
                role: SystemTunnelRole::WebConsole,
                config: TunnelConfig {
                    name: "Web Console".to_string(),
                    local_port: 9,
                    to: "localhost".to_string(),
                    port: Some(7836),
                    local_host: "127.0.0.1".to_string(),
                    secret: None,
                },
                display_url: Some("https://localhost:7836".to_string()),
            },
            SystemTunnelSpec {
                role: SystemTunnelRole::Ssh,
                config: TunnelConfig {
                    name: "SSH".to_string(),
                    local_port: 9,
                    to: "localhost".to_string(),
                    port: Some(2222),
                    local_host: "127.0.0.1".to_string(),
                    secret: None,
                },
                display_url: Some("localhost:2222".to_string()),
            },
        ],
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    for _ in 0..250 {
        let tunnels = state.list_tunnels().await;
        if tunnels.len() == 2
            && tunnels
                .iter()
                .all(|tunnel| tunnel.status == ltr_cli::web::TunnelStatus::Running)
        {
            assert!(tunnels.iter().all(|tunnel| tunnel.locked));
            break;
        }
        time::sleep(Duration::from_millis(20)).await;
    }

    let session = state.session().await;
    assert_eq!(
        session.web_remote_url.as_deref(),
        Some("https://localhost:7836")
    );
    assert_eq!(
        session.ssh_remote_endpoint.as_deref(),
        Some("localhost:2222")
    );

    let _ = shutdown_tx.send(());
    task.await??;
    Ok(())
}
