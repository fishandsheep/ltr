#![allow(missing_docs)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Serialize;

use super::state::{SessionInfo, StateError, TunnelConfig, TunnelInfo, WebState};

pub fn router() -> Router<WebState> {
    Router::new()
        .route("/session", get(get_session))
        .route("/tunnels", get(list_tunnels).post(create_tunnel))
        .route("/tunnels/:id", put(update_tunnel).delete(delete_tunnel))
        .route("/tunnels/:id/start", post(start_tunnel))
        .route("/tunnels/:id/stop", post(stop_tunnel))
        .route("/tunnels/:id/logs", get(get_logs))
}

#[derive(Debug, Serialize)]
struct TunnelIdResponse {
    id: String,
}

#[derive(Debug, Serialize)]
struct AckResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    logs: Vec<String>,
}

async fn get_session(State(state): State<WebState>) -> Json<SessionInfo> {
    Json(state.session().await)
}

async fn list_tunnels(State(state): State<WebState>) -> Json<Vec<TunnelInfo>> {
    Json(state.list_tunnels().await)
}

async fn create_tunnel(
    State(state): State<WebState>,
    Json(config): Json<TunnelConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let id = state.create_tunnel(config).await?;
    Ok((StatusCode::CREATED, Json(TunnelIdResponse { id })))
}

async fn start_tunnel(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Result<Json<AckResponse>, ApiError> {
    state.start_tunnel(&id).await?;
    Ok(Json(AckResponse { ok: true }))
}

async fn update_tunnel(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(config): Json<TunnelConfig>,
) -> Result<Json<AckResponse>, ApiError> {
    state.update_tunnel(&id, config).await?;
    Ok(Json(AckResponse { ok: true }))
}

async fn stop_tunnel(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Result<Json<AckResponse>, ApiError> {
    state.stop_tunnel(&id).await?;
    Ok(Json(AckResponse { ok: true }))
}

async fn delete_tunnel(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Result<Json<AckResponse>, ApiError> {
    state.delete_tunnel(&id).await?;
    Ok(Json(AckResponse { ok: true }))
}

async fn get_logs(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> Result<Json<LogsResponse>, ApiError> {
    let logs = state.logs(&id).await?;
    Ok(Json(LogsResponse { logs }))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl From<StateError> for ApiError {
    fn from(value: StateError) -> Self {
        Self {
            status: value.status,
            message: value.message,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}
