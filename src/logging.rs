// Structured logging setup — tracing + tracing-subscriber.
// Outputs:
//   - stderr: human-readable (colored, compact)
//   - storage/logs/uv.YYYY-MM-DD.log: JSON (machine-readable, daily rotation)

use std::path::Path;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

pub struct LogGuard {
    _guard: tracing_appender::non_blocking::WorkerGuard,
}

/// Initialize tracing. Call once at startup.
/// `log_dir`: path to log directory (e.g. "storage/logs").
/// `verbosity`: 0=warn, 1=info, 2=debug, 3=trace.
/// Returns a guard — must be kept alive until program exit.
pub fn init(log_dir: impl AsRef<Path>, verbosity: u8) -> LogGuard {
    let base_level = match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    // File appender — daily rotation, storage/logs/uv.YYYY-MM-DD.log
    let file_appender = RollingFileAppender::new(Rotation::DAILY, log_dir.as_ref(), "uv.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // File layer — JSON, no color, full timestamps
    let file_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_writer(non_blocking)
        .with_filter(
            EnvFilter::from_default_env().add_directive(format!("{base_level}").parse().unwrap()),
        );

    // Stderr layer — compact, colored for human reading
    let stderr_layer = fmt::layer()
        .compact()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(
            EnvFilter::from_env("UV_LOG").add_directive(format!("{base_level}").parse().unwrap()),
        );

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer)
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %log_dir.as_ref().display(),
        "uv started"
    );

    LogGuard { _guard: guard }
}
