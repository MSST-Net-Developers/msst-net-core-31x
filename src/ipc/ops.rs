//! Background operations — commands sent with `async: true` (protocol 0.4).
//!
//! ```text
//! Request{async:true, CreateRoom}  → Response Ok {"operation_id": "op-7"}
//!                                  → Event OperationProgress {op-7, "relay_selected"} …
//!                                  → Event OperationCompleted {op-7, "create_room", result}
//! GetOperation {op-7}              → running (with the last stage) or the result
//! ```
//!
//! `result` is exactly what the synchronous request would have returned.
//! At most [`MAX_RUNNING`] operations run at once (Core-wide); beyond that
//! the request fails with `busy` (bounded, AGENTS.md §3.6).  Finished
//! operations stay queryable for [`KEEP_FINISHED_SECS`] (at most
//! [`KEEP_FINISHED`]), so a Controller that reconnects mid-operation can
//! still learn the outcome.  Operations outlive the connection that
//! started them: Core owns them, not the Controller.
//!
//! Long-running code reports steps with [`progress`]; it is a no-op outside
//! an operation, so the synchronous path is unaffected.

use super::Session;
use crate::state::CoreState;
use msst_ipc_protocol::views::{OperationStatus, OperationView};
use msst_ipc_protocol::{IpcError, IpcEvent, IpcRequest, IpcResponse};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, Semaphore};
use tracing::{debug, info};

/// Operations running at once, Core-wide.
pub const MAX_RUNNING: usize = 16;
/// Finished operations remembered.
pub const KEEP_FINISHED: usize = 64;
/// How long a finished operation stays queryable.
pub const KEEP_FINISHED_SECS: i64 = 600;

tokio::task_local! {
    /// The operation the current task is running, if any.
    static CURRENT: (String, Arc<CoreState>);
}

/// Report a step of the current operation (`OperationProgress`).  No-op
/// outside an operation.
pub fn progress(stage: &str) {
    let _ = CURRENT.try_with(|(id, state)| {
        state.operations.set_stage(id, stage);
        state.emit_ipc_event(IpcEvent::OperationProgress { operation_id: id.clone(), stage: stage.to_string() });
    });
}

#[derive(Debug, Clone)]
enum OpState {
    Running { stage: Option<String> },
    Done { result: IpcResponse, finished_unix: i64 },
}

#[derive(Debug, Clone)]
struct OpEntry {
    request_type: String,
    started_unix: i64,
    state: OpState,
}

#[derive(Default)]
struct Table {
    next: u64,
    entries: HashMap<String, OpEntry>,
    /// Finished operation IDs, oldest first.
    finished: VecDeque<String>,
}

/// The operation table (in `CoreState`).
pub struct Operations {
    table: Mutex<Table>,
    running: Arc<Semaphore>,
}

impl Default for Operations {
    fn default() -> Self {
        Operations { table: Mutex::new(Table::default()), running: Arc::new(Semaphore::new(MAX_RUNNING)) }
    }
}

/// The request's wire `type`, e.g. `"create_room"`.
pub fn request_type(req: &IpcRequest) -> String {
    serde_json::to_value(req).ok().and_then(|v| v["type"].as_str().map(str::to_string)).unwrap_or_default()
}

impl Operations {
    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_stage(&self, id: &str, stage: &str) {
        if let Some(OpEntry { state: OpState::Running { stage: s }, .. }) = self.lock().entries.get_mut(id) {
            *s = Some(stage.to_string());
        }
    }

    fn finish(&self, id: &str, result: IpcResponse, now: i64) {
        let mut t = self.lock();
        if let Some(e) = t.entries.get_mut(id) {
            e.state = OpState::Done { result, finished_unix: now };
        }
        t.finished.push_back(id.to_string());
        Self::prune(&mut t, now);
    }

    fn prune(t: &mut Table, now: i64) {
        while let Some(old) = t.finished.front().cloned() {
            let expired = match t.entries.get(&old) {
                Some(OpEntry { state: OpState::Done { finished_unix, .. }, .. }) => {
                    now.saturating_sub(*finished_unix) >= KEEP_FINISHED_SECS
                }
                _ => true,
            };
            if !expired && t.finished.len() <= KEEP_FINISHED {
                break;
            }
            t.finished.pop_front();
            t.entries.remove(&old);
        }
    }

    /// `GetOperation`.
    pub fn view(&self, id: &str, now: i64) -> Option<OperationView> {
        let mut t = self.lock();
        Self::prune(&mut t, now);
        let e = t.entries.get(id)?;
        let mut v = OperationView {
            operation_id: id.to_string(),
            request_type: e.request_type.clone(),
            status: OperationStatus::Running,
            stage: None,
            result: None,
            started_at: e.started_unix,
            finished_at: None,
        };
        match &e.state {
            OpState::Running { stage } => v.stage = stage.clone(),
            OpState::Done { result, finished_unix } => {
                v.status = OperationStatus::Completed;
                v.result = Some(result.clone());
                v.finished_at = Some(*finished_unix);
            }
        }
        Some(v)
    }
}

/// Accept `body` as a background operation.  Returns its ID and a trigger:
/// the operation starts when the trigger is dropped or fired, so the
/// caller can queue the "accepted" response first (an `OperationCompleted`
/// can then never overtake it).
pub fn start(state: &Arc<CoreState>, session: Arc<Session>, body: IpcRequest) -> Result<(String, oneshot::Sender<()>), IpcError> {
    let required = body.required_role();
    if required > session.role {
        return Err(IpcError {
            code: "permission_denied".into(),
            message: format!("this connection is {}; the request needs {}", session.role.as_str(), required.as_str()),
        });
    }
    let permit = state.operations.running.clone().try_acquire_owned().map_err(|_| IpcError {
        code: "busy".into(),
        message: format!("{} operations are already running", MAX_RUNNING),
    })?;
    let now = crate::runtime::current_unix();
    let request_type = request_type(&body);
    let id = {
        let mut t = state.operations.lock();
        t.next += 1;
        let id = format!("op-{}", t.next);
        t.entries.insert(id.clone(), OpEntry { request_type: request_type.clone(), started_unix: now, state: OpState::Running { stage: None } });
        id
    };
    info!("IPC: operation {} ({}) accepted", id, request_type);
    let (go_tx, go_rx) = oneshot::channel::<()>();
    let (state, op_id) = (state.clone(), id.clone());
    tokio::spawn(async move {
        let _ = go_rx.await;
        let result = CURRENT
            .scope((op_id.clone(), state.clone()), super::handler::handle_request(body, &state, &session))
            .await;
        debug!("IPC: operation {} finished", op_id);
        state.operations.finish(&op_id, result.clone(), crate::runtime::current_unix());
        state.emit_ipc_event(IpcEvent::OperationCompleted { operation_id: op_id, request_type, result });
        drop(permit);
    });
    Ok((id, go_tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use msst_ipc_protocol::Role;

    #[test]
    fn finished_operations_expire_and_are_capped() {
        let ops = Operations::default();
        let ok = IpcResponse::Ok(serde_json::json!({}));
        for i in 0..KEEP_FINISHED + 5 {
            let id = format!("op-{}", i);
            ops.lock().entries.insert(id.clone(), OpEntry { request_type: "x".into(), started_unix: 0, state: OpState::Running { stage: None } });
            ops.finish(&id, ok.clone(), 100);
        }
        assert!(ops.view("op-0", 100).is_none(), "oldest dropped beyond the cap");
        let last = format!("op-{}", KEEP_FINISHED + 4);
        assert_eq!(ops.view(&last, 100).unwrap().status, OperationStatus::Completed);
        assert!(ops.view(&last, 100 + KEEP_FINISHED_SECS).is_none(), "expired");
    }

    #[tokio::test]
    async fn async_command_reports_progress_and_completion() {
        let (state, mut rx) = crate::test_support::core_state("ops").await;
        let session = Arc::new(Session::new(Role::Admin));
        let (id, go) = start(&state, session.clone(), IpcRequest::SetPingEnabled { enabled: true }).unwrap();
        assert_eq!(state.operations.view(&id, 0).unwrap().status, OperationStatus::Running);
        drop(go);
        let mut completed = None;
        for _ in 0..100 {
            if let Ok(IpcEvent::OperationCompleted { operation_id, request_type, result }) = rx.try_recv() {
                completed = Some((operation_id, request_type, result));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let (op, ty, result) = completed.expect("OperationCompleted");
        assert_eq!((op.as_str(), ty.as_str()), (id.as_str(), "set_ping_enabled"));
        assert!(matches!(result, IpcResponse::Ok(_)));
        assert!(state.net.read().await.ping_enabled);
        let v = state.operations.view(&id, crate::runtime::current_unix()).unwrap();
        assert_eq!(v.status, OperationStatus::Completed);
        assert!(matches!(v.result, Some(IpcResponse::Ok(_))));

        // Viewers are refused up front; nothing is recorded.
        let viewer = Arc::new(Session::new(Role::Viewer));
        assert_eq!(start(&state, viewer, IpcRequest::ClearAclRules).unwrap_err().code, "permission_denied");
    }

    #[tokio::test]
    async fn progress_outside_an_operation_is_a_no_op() {
        progress("anything");
        let (state, mut rx) = crate::test_support::core_state("ops-progress").await;
        let st = state.clone();
        CURRENT.scope(("op-x".into(), st), async { progress("relay_selected") }).await;
        assert!(matches!(rx.try_recv(), Ok(IpcEvent::OperationProgress { operation_id, stage }) if operation_id == "op-x" && stage == "relay_selected"));
    }

    #[tokio::test]
    async fn running_operations_are_bounded() {
        let (state, _rx) = crate::test_support::core_state("ops-busy").await;
        let session = Arc::new(Session::new(Role::Admin));
        let mut held = Vec::new();
        for _ in 0..MAX_RUNNING {
            // Never fired: the operations stay queued, holding their permits.
            held.push(start(&state, session.clone(), IpcRequest::ClearLogs).unwrap().1);
        }
        assert_eq!(start(&state, session, IpcRequest::ClearLogs).unwrap_err().code, "busy");
        let _keep = held;
    }
}
