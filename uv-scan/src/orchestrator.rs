// Orchestrator — ties pipeline + output together.
// Command pattern: execute() is the command entry point.

use uv_core::error::UvResult;
use uv_core::types::result::ScanResult;
use uv_output::make_formatter;

use crate::job::ScanJob;
use crate::pipeline;

pub struct Orchestrator {
    job: ScanJob,
}

impl Orchestrator {
    pub fn new(job: ScanJob) -> Self {
        Self { job }
    }

    /// Execute the full scan and return formatted output.
    pub async fn execute(&self) -> UvResult<String> {
        let result = pipeline::run(&self.job).await;
        let formatted = self.format(&result);
        Ok(formatted)
    }

    /// Execute and return raw result (caller formats).
    pub async fn execute_raw(&self) -> UvResult<ScanResult> {
        Ok(pipeline::run(&self.job).await)
    }

    fn format(&self, result: &ScanResult) -> String {
        make_formatter(self.job.output_format).format(result)
    }
}
