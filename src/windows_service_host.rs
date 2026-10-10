//! Windows service host (ported from 3.0.x `main.rs`).
//!
//! The SCM requires `StartServiceCtrlDispatcher` within ~30 s of launch.
//! When the binary is started by hand there is no SCM and the call fails
//! with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) — then Core runs in
//! the console instead (Ctrl+C to stop).

#![cfg(windows)]

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// Service name registered with the SCM (same as 3.0.x).
pub const SERVICE_NAME: &str = "msst-net";
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// Run as a service if started by the SCM.  `None` = not under the SCM;
/// the caller should run in the console.
pub fn dispatch() -> Option<anyhow::Result<()>> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Some(Ok(())),
        Err(windows_service::Error::Winapi(ref e)) if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => {
            eprintln!("未检测到 Windows 服务控制管理器，改为在控制台前台运行（调试模式）");
            None
        }
        Err(e) => Some(Err(anyhow::anyhow!("服务调度器错误: {}", e))),
    }
}

define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32, wait: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Arc::new(Mutex::new(Some(stop_tx)));
    let handler_tx = stop_tx.clone();
    let handle = match service_control_handler::register(SERVICE_NAME, move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = handler_tx.lock().ok().and_then(|mut g| g.take()) {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("无法注册服务控制处理器: {}", e);
            return;
        }
    };

    let _ = handle.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty(), 0, Duration::from_secs(30)));

    let result = crate::load_config().and_then(|config| {
        let rt = crate::build_runtime()?;
        let _ = handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::default(),
        ));
        rt.block_on(crate::run(config, async {
            let _ = stop_rx.await;
            tracing::info!("service stop requested by the SCM");
        }))
    });
    let exit = match &result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("服务运行错误: {}", e);
            1
        }
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), exit, Duration::default()));
}
