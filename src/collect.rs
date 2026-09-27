//! A sink that keeps everything in memory, for the benchmark and for tests.

use std::sync::{Arc, Mutex};

use forensic_rs::prelude::*;

/// Clone it, give one clone to the pipeline, read the other after the run.
#[derive(Clone, Default)]
pub struct Collector {
    records: Arc<Mutex<Vec<ForensicData>>>,
    findings: Arc<Mutex<Vec<Finding>>>,
}

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<ForensicData> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    pub fn findings(&self) -> Vec<Finding> {
        self.findings.lock().map(|f| f.clone()).unwrap_or_default()
    }
}

impl TriageSink for Collector {
    fn name(&self) -> &str {
        "collector"
    }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        self.records
            .lock()
            .map_err(|_| ForensicError::other("collector", "record list poisoned".into()))?
            .push(data.clone());
        Ok(())
    }

    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        self.findings
            .lock()
            .map_err(|_| ForensicError::other("collector", "finding list poisoned".into()))?
            .push(finding.clone());
        Ok(())
    }
}
