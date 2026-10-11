// uv-scan: high-level scan orchestrator.
// Facade over uv-engine, uv-proto, uv-crypto, uv-output, uv-os.

pub mod dedup;
pub mod job;
pub mod orchestrator;
pub mod pipeline;
pub mod resume;
pub mod status;
pub mod throttle;
pub mod tracer;

pub use job::{ScanJob, ScanJobBuilder};
pub use orchestrator::Orchestrator;
pub use resume::ResumeState;
pub use status::ScanStatus;
pub use throttle::Throttle;
