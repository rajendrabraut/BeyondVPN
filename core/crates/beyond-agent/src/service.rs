//! Native Windows service (Service Control Manager): `beyond-agent service install|uninstall|run`.
//!
//! The service runs as LocalSystem with its state in %ProgramData%\BeyondVPN (SYSTEM and
//! Administrators only; agent.token also readable by signed-in users for the desktop app).
//! It reports Running/Stopped to the SCM and is restarted by the SCM after a crash.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
    ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "BeyondVPNAgent";
const DISPLAY: &str = "Beyond VPN Agent";

static PORT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Entry point used by the SCM (`service run`). Blocks until the service stops.
pub fn run(port: u16) -> anyhow::Result<()> {
    let _ = PORT.set(port);
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| anyhow::anyhow!("not started by the Service Control Manager ({e}); use `beyond-agent service install`"))
}

fn service_main(_args: Vec<OsString>) {
    let dir = crate::store::service_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("agent.log")) {
        let _ = tracing_subscriber::fmt().with_writer(std::sync::Mutex::new(f)).with_ansi(false).try_init();
    }
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service failed");
    }
}

fn status(state: ServiceState, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let handle = service_control_handler::register(NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::StartPending, 0))?;

    let port = *PORT.get().unwrap_or(&47800);
    let result = (|| -> anyhow::Result<()> {
        let store = crate::store::Store::open(crate::store::service_dir())?;
        store.harden_for_service()?;
        let backend = crate::tunnel::platform_backend(&store.dir);
        let engine = Arc::new(crate::engine::Engine::new(store, backend));
        let rt = tokio::runtime::Runtime::new()?;
        handle.set_service_status(status(ServiceState::Running, 0))?;
        tracing::info!(port, "service running");
        rt.block_on(async move {
            let stop = tokio::task::spawn_blocking(move || stop_rx.recv());
            tokio::select! {
                r = crate::server::serve(engine, port) => r,
                // The WireGuard tunnel service is independent: stopping the agent (e.g. for an
                // update) leaves an active tunnel up; the agent picks it up again on start.
                _ = stop => Ok(()),
            }
        })
    })();
    let code = match &result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, "service stopped with error");
            1064 // ERROR_EXCEPTION_IN_SERVICE
        }
    };
    handle.set_service_status(status(ServiceState::Stopped, code))?;
    result
}

/// Register the service (auto start, LocalSystem, restart on failure) and start it.
pub fn install(port: u16, allow_any_path: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    // A LocalSystem service whose binary normal users can replace is a privilege escalation.
    anyhow::ensure!(
        allow_any_path || exe.starts_with(&pf),
        "refusing to install a SYSTEM service from {} (copy beyond-agent.exe under {pf} first, or pass --allow-any-path for testing)",
        exe.display()
    );
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["service".into(), "run".into(), "--port".into(), port.to_string().into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    svc.set_description(format!("Beyond VPN tunnel manager (local API on 127.0.0.1:{port})"))?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
        ]),
    })?;
    svc.start::<&str>(&[])?;
    Ok(())
}

/// Stop (if running) and remove the service. State in %ProgramData%\BeyondVPN is kept.
pub fn uninstall() -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        for _ in 0..40 {
            if svc.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    svc.delete()?;
    Ok(())
}
