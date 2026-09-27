//! The pipeline-readiness benchmark: can a parser run unattended inside a pipeline?
//!
//! Every parser in the [`Catalog`] goes through the same checks, over the same corpora
//! ([`crate::fixtures`], plus any evidence given on the command line):
//!
//! | check | passes when |
//! |---|---|
//! | `descriptor` | the id is non-empty and unique, a version is set, and artifacts are declared |
//! | `empty` | with no filesystem and no registry it neither panics nor emits a record |
//! | `garbage` | hostile bytes at every artifact path never panic it, and the run completes |
//! | `coverage` | it emits records on at least one valid corpus (informational: `skip` = untested) |
//! | `determinism` | two runs over the same input give identical records and findings |
//! | `cancellation` | once the pipeline says stop, it emits nothing more |
//! | `provenance` | every record's provenance resolves, carries the run's host, and `@timestamp` is a date |
//! | `parallel` | the parallel pipeline yields the same records as the serial one |
//!
//! Checks that need records are skipped when no corpus gives the parser any.

use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use forensic_rs::prelude::*;
use serde::Serialize;

use crate::catalog::Catalog;
use crate::collect::Collector;
use crate::fixtures::{Corpus, CorpusKind};
use crate::run::{gaps, GapSummary};

const HOST: &str = "BENCH-HOST";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    Fail,
    Skip,
}

impl Outcome {
    fn symbol(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "**FAIL**",
            Outcome::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub check: &'static str,
    pub outcome: Outcome,
    pub detail: String,
}

impl CheckResult {
    fn new(check: &'static str, outcome: Outcome, detail: impl Into<String>) -> Self {
        Self {
            check,
            outcome,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ParserReport {
    #[serde(rename = "crate")]
    pub crate_name: &'static str,
    pub parser: String,
    pub checks: Vec<CheckResult>,
}

impl ParserReport {
    pub fn check(&self, name: &str) -> Option<&CheckResult> {
        self.checks.iter().find(|c| c.check == name)
    }

    /// Pipeline-ready: no check failed.
    pub fn ready(&self) -> bool {
        self.checks.iter().all(|c| c.outcome != Outcome::Fail)
    }
}

#[derive(Debug, Serialize)]
pub struct ReadinessMatrix {
    pub tool_version: &'static str,
    pub corpora: Vec<String>,
    pub parsers: Vec<ParserReport>,
    pub gaps: Vec<GapSummary>,
}

pub const CHECKS: [&str; 8] = [
    "descriptor",
    "empty",
    "garbage",
    "coverage",
    "determinism",
    "cancellation",
    "provenance",
    "parallel",
];

/// Runs every check for every catalog parser over `corpora`.
pub fn benchmark(catalog: &Catalog, corpora: &[Corpus]) -> ReadinessMatrix {
    // Panics are expected results here, not noise for the terminal.
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let ids: Vec<String> = catalog
        .parsers()
        .map(|(_, p)| p.descriptor().id.to_string())
        .collect();
    let parsers = catalog
        .parsers()
        .map(|(crate_name, parser)| ParserReport {
            crate_name,
            parser: parser.descriptor().id.to_string(),
            checks: check_parser(parser, &ids, corpora),
        })
        .collect();
    panic::set_hook(hook);
    ReadinessMatrix {
        tool_version: env!("CARGO_PKG_VERSION"),
        corpora: corpora.iter().map(|c| c.name.clone()).collect(),
        parsers,
        gaps: gaps(catalog),
    }
}

fn check_parser(
    parser: &Arc<dyn ArtifactParserFactory>,
    ids: &[String],
    corpora: &[Corpus],
) -> Vec<CheckResult> {
    let mut checks = vec![descriptor(parser, ids)];

    // One observed run per corpus; the record-hungry checks reuse it as their baseline.
    let runs: Vec<(&Corpus, Result<Observed, String>)> = corpora
        .iter()
        .map(|c| (c, observe(parser, &c.sources, None)))
        .collect();

    checks.push(empty(&runs));
    checks.push(garbage(&runs));
    checks.push(coverage(&runs));

    let with_records: Vec<(&Corpus, &Observed)> = runs
        .iter()
        .filter_map(|(c, r)| {
            r.as_ref()
                .ok()
                .filter(|o| !o.records.is_empty())
                .map(|o| (*c, o))
        })
        .collect();
    if with_records.is_empty() {
        for check in ["determinism", "cancellation", "provenance", "parallel"] {
            checks.push(CheckResult::new(
                check,
                Outcome::Skip,
                "no corpus gives this parser any record",
            ));
        }
        return checks;
    }
    checks.push(determinism(parser, &with_records));
    checks.push(cancellation(parser, &with_records));
    checks.push(provenance(&with_records));
    checks.push(parallel(parser, &with_records));
    checks
}

fn descriptor(parser: &Arc<dyn ArtifactParserFactory>, ids: &[String]) -> CheckResult {
    let d = parser.descriptor();
    let mut problems = Vec::new();
    if d.id.trim().is_empty() {
        problems.push("empty id".to_string());
    }
    if ids.iter().filter(|i| **i == *d.id).count() > 1 {
        problems.push(format!("id `{}` is not unique", d.id));
    }
    if d.version.trim().is_empty() {
        problems.push("no version".into());
    }
    if d.artifacts.is_empty() {
        problems.push("declares no artifact, so it matches every analyzer".into());
    }
    if problems.is_empty() {
        CheckResult::new(
            "descriptor",
            Outcome::Pass,
            format!("{} v{}", d.id, d.version),
        )
    } else {
        CheckResult::new("descriptor", Outcome::Fail, problems.join("; "))
    }
}

fn empty(runs: &[(&Corpus, Result<Observed, String>)]) -> CheckResult {
    let Some((_, run)) = runs.iter().find(|(c, _)| c.kind == CorpusKind::Empty) else {
        return CheckResult::new("empty", Outcome::Skip, "no empty corpus");
    };
    match run {
        Err(panic) => CheckResult::new("empty", Outcome::Fail, format!("panicked: {panic}")),
        Ok(o) if !o.records.is_empty() => CheckResult::new(
            "empty",
            Outcome::Fail,
            format!("emitted {} record(s) from no evidence", o.records.len()),
        ),
        Ok(o) => CheckResult::new("empty", Outcome::Pass, o.describe()),
    }
}

fn garbage(runs: &[(&Corpus, Result<Observed, String>)]) -> CheckResult {
    let garbage: Vec<_> = runs
        .iter()
        .filter(|(c, _)| c.kind == CorpusKind::Garbage)
        .collect();
    if garbage.is_empty() {
        return CheckResult::new("garbage", Outcome::Skip, "no garbage corpus");
    }
    let panics: Vec<String> = garbage
        .iter()
        .filter_map(|(c, r)| r.as_ref().err().map(|p| format!("{}: {p}", c.name)))
        .collect();
    if !panics.is_empty() {
        return CheckResult::new(
            "garbage",
            Outcome::Fail,
            format!("panicked on {}", panics.join("; ")),
        );
    }
    let (records, errors) = garbage
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok())
        .fold((0, 0), |(r, e), o| (r + o.records.len(), e + o.errors));
    CheckResult::new(
        "garbage",
        Outcome::Pass,
        format!(
            "{} corpora, {records} record(s), {errors} error(s), no panic",
            garbage.len()
        ),
    )
}

fn coverage(runs: &[(&Corpus, Result<Observed, String>)]) -> CheckResult {
    let hits: Vec<String> = runs
        .iter()
        .filter(|(c, _)| matches!(c.kind, CorpusKind::Valid | CorpusKind::External))
        .filter_map(|(c, r)| {
            r.as_ref()
                .ok()
                .filter(|o| !o.records.is_empty())
                .map(|o| format!("{}: {}", c.name, o.records.len()))
        })
        .collect();
    if hits.is_empty() {
        CheckResult::new(
            "coverage",
            Outcome::Skip,
            "no valid corpus exercises this parser",
        )
    } else {
        CheckResult::new("coverage", Outcome::Pass, hits.join(", "))
    }
}

fn determinism(
    parser: &Arc<dyn ArtifactParserFactory>,
    with_records: &[(&Corpus, &Observed)],
) -> CheckResult {
    for (corpus, first) in with_records {
        let second = match observe(parser, &corpus.sources, None) {
            Ok(o) => o,
            Err(p) => {
                return CheckResult::new(
                    "determinism",
                    Outcome::Fail,
                    format!("{}: second run panicked: {p}", corpus.name),
                )
            }
        };
        if first.record_lines != second.record_lines {
            let at = first
                .record_lines
                .iter()
                .zip(&second.record_lines)
                .position(|(a, b)| a != b)
                .unwrap_or(first.record_lines.len().min(second.record_lines.len()));
            return CheckResult::new(
                "determinism",
                Outcome::Fail,
                format!(
                    "{}: records differ between runs at #{at} ({} vs {} records)",
                    corpus.name,
                    first.record_lines.len(),
                    second.record_lines.len()
                ),
            );
        }
        if first.finding_lines != second.finding_lines {
            return CheckResult::new(
                "determinism",
                Outcome::Fail,
                format!("{}: findings differ between runs", corpus.name),
            );
        }
    }
    CheckResult::new(
        "determinism",
        Outcome::Pass,
        format!("{} corpora, identical output", with_records.len()),
    )
}

fn cancellation(
    parser: &Arc<dyn ArtifactParserFactory>,
    with_records: &[(&Corpus, &Observed)],
) -> CheckResult {
    let Some((corpus, full)) = with_records.iter().find(|(_, o)| o.records.len() >= 2) else {
        return CheckResult::new(
            "cancellation",
            Outcome::Skip,
            "needs a corpus with at least two records",
        );
    };
    match observe(parser, &corpus.sources, Some(1)) {
        Err(p) => CheckResult::new(
            "cancellation",
            Outcome::Fail,
            format!("{}: panicked: {p}", corpus.name),
        ),
        Ok(o) if o.emitted_after_stop > 0 => CheckResult::new(
            "cancellation",
            Outcome::Fail,
            format!(
                "{}: kept emitting {} record(s) after the pipeline said stop",
                corpus.name, o.emitted_after_stop
            ),
        ),
        Ok(o) if o.records.len() >= full.records.len() => CheckResult::new(
            "cancellation",
            Outcome::Fail,
            format!(
                "{}: delivered all {} records despite cancellation",
                corpus.name,
                o.records.len()
            ),
        ),
        Ok(o) => CheckResult::new(
            "cancellation",
            Outcome::Pass,
            format!(
                "{}: stopped after {} of {} records",
                corpus.name,
                o.records.len(),
                full.records.len()
            ),
        ),
    }
}

fn provenance(with_records: &[(&Corpus, &Observed)]) -> CheckResult {
    let mut problems = Vec::new();
    let mut checked = 0usize;
    for (corpus, o) in with_records {
        for (i, r) in o.records.iter().enumerate() {
            checked += 1;
            if o.store.get(r.provenance()).is_none() {
                problems.push(format!(
                    "{} #{i}: provenance id not in the run's store",
                    corpus.name
                ));
            }
            if r.host() != HOST {
                problems.push(format!(
                    "{} #{i}: host is `{}`, not the run's host",
                    corpus.name,
                    r.host()
                ));
            }
            if let Some(ts) = r.field("@timestamp") {
                if !matches!(ts, Field::Date(_)) {
                    problems.push(format!("{} #{i}: @timestamp is not a date", corpus.name));
                }
            }
            if problems.len() >= 3 {
                break;
            }
        }
    }
    if problems.is_empty() {
        CheckResult::new(
            "provenance",
            Outcome::Pass,
            format!("{checked} record(s) checked"),
        )
    } else {
        CheckResult::new("provenance", Outcome::Fail, problems.join("; "))
    }
}

fn parallel(
    parser: &Arc<dyn ArtifactParserFactory>,
    with_records: &[(&Corpus, &Observed)],
) -> CheckResult {
    for (corpus, serial) in with_records {
        let par = match observe_parallel(parser, &corpus.sources) {
            Ok(Ok(lines)) => lines,
            Ok(Err(e)) => {
                return CheckResult::new("parallel", Outcome::Fail, format!("{}: {e}", corpus.name))
            }
            Err(p) => {
                return CheckResult::new(
                    "parallel",
                    Outcome::Fail,
                    format!("{}: panicked: {p}", corpus.name),
                )
            }
        };
        let mut expected = serial.record_lines.clone();
        expected.sort();
        if par != expected {
            return CheckResult::new(
                "parallel",
                Outcome::Fail,
                format!(
                    "{}: {} records in parallel vs {} serial, or different content",
                    corpus.name,
                    par.len(),
                    expected.len()
                ),
            );
        }
    }
    CheckResult::new(
        "parallel",
        Outcome::Pass,
        format!("{} corpora, same records", with_records.len()),
    )
}

/// What one serial run produced.
struct Observed {
    records: Vec<ForensicData>,
    record_lines: Vec<String>,
    finding_lines: Vec<String>,
    errors: usize,
    emitted_after_stop: u64,
    store: ProvenanceStore,
}

impl Observed {
    fn describe(&self) -> String {
        format!("{} record(s), {} error(s)", self.records.len(), self.errors)
    }
}

/// One serial run of `parser` alone. `cancel_after`: cancel once that many records arrived.
/// `Err` carries the panic message.
fn observe(
    parser: &Arc<dyn ArtifactParserFactory>,
    sources: &TriageSources,
    cancel_after: Option<usize>,
) -> Result<Observed, String> {
    let watched = Arc::new(StopWatch::new(Arc::clone(parser)));
    let after_stop = Arc::clone(&watched.after_stop);
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        let ctx = TriageContext::new(HOST, "bench");
        let store = ctx.provenance_store();
        let collector = Collector::new();
        let token = CancellationToken::new();
        let mut builder = TriagePipeline::builder()
            .context(ctx)
            .parser(watched)
            .sink(Box::new(collector.clone()))
            .on_parser_error(ErrorAction::Continue);
        if let Some(n) = cancel_after {
            builder = builder.sink(Box::new(Canceller {
                token: token.clone(),
                after: n,
                seen: 0,
            }));
        }
        let mut pipeline = builder.build().map_err(|e| e.to_string())?;
        let result = pipeline
            .run_with_cancellation(sources, token)
            .map_err(|e| e.to_string())?;
        let records = collector.records();
        let findings = collector.findings();
        Ok::<_, String>(Observed {
            record_lines: records.iter().map(json).collect(),
            finding_lines: findings.iter().map(finding_line).collect(),
            records,
            errors: result.errors.len(),
            emitted_after_stop: 0,
            store,
        })
    }));
    match caught {
        Ok(Ok(mut o)) => {
            o.emitted_after_stop = after_stop.load(Ordering::Relaxed);
            Ok(o)
        }
        Ok(Err(e)) => Err(format!("run aborted: {e}")),
        Err(payload) => Err(panic_message(payload)),
    }
}

/// Sorted record lines from a parallel run of `parser` alone.
fn observe_parallel(
    parser: &Arc<dyn ArtifactParserFactory>,
    sources: &TriageSources,
) -> Result<Result<Vec<String>, String>, String> {
    let s = sources.clone();
    let parser = Arc::clone(parser);
    panic::catch_unwind(AssertUnwindSafe(move || {
        let collector = Collector::new();
        let task = StandardParallelTaskBuilder::new(parser.descriptor().id.to_string())
            .parser(parser)
            .sources(move || s)
            .on_error(ErrorAction::Continue)
            .build()
            .map_err(|e| e.to_string())?;
        let mut pipeline = ParallelPipeline::builder()
            .context(TriageContext::new(HOST, "bench"))
            .workers(2)
            .task(Box::new(task))
            .sink(Box::new(collector.clone()))
            .build()
            .map_err(|e| e.to_string())?;
        pipeline.run().map_err(|e| e.to_string())?;
        let mut lines: Vec<String> = collector.records().iter().map(json).collect();
        lines.sort();
        Ok(lines)
    }))
    .map_err(panic_message)
}

fn json(d: &ForensicData) -> String {
    serde_json::to_string(d).unwrap_or_else(|e| format!("<unserializable record: {e}>"))
}

fn finding_line(f: &Finding) -> String {
    serde_json::to_string(f).unwrap_or_else(|e| format!("<unserializable finding: {e}>"))
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".into())
}

/// Cancels the run once `after` records reached the sinks.
struct Canceller {
    token: CancellationToken,
    after: usize,
    seen: usize,
}

impl TriageSink for Canceller {
    fn name(&self) -> &str {
        "canceller"
    }
    fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
        self.seen += 1;
        if self.seen >= self.after {
            self.token.cancel();
        }
        Ok(())
    }
    fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
        Ok(())
    }
}

/// Wraps a factory and counts records a push parser emits after being told to stop. A pull
/// parser cannot do that: the pipeline simply stops pulling.
struct StopWatch {
    inner: Arc<dyn ArtifactParserFactory>,
    after_stop: Arc<AtomicU64>,
}

impl StopWatch {
    fn new(inner: Arc<dyn ArtifactParserFactory>) -> Self {
        Self {
            inner,
            after_stop: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ArtifactParserFactory for StopWatch {
    fn descriptor(&self) -> &ParserDescriptor {
        self.inner.descriptor()
    }
    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        self.inner.can_parse(ctx)
    }
    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        Ok(match self.inner.open(ctx)? {
            ParserRun::Pull(stream) => ParserRun::Pull(stream),
            ParserRun::Push(drive) => {
                let after_stop = Arc::clone(&self.after_stop);
                ParserRun::push(move |out| {
                    let mut watch = Watch {
                        out,
                        stopped: false,
                        after_stop,
                    };
                    drive(&mut watch)
                })
            }
        })
    }
}

struct Watch<'a> {
    out: &'a mut dyn ParserOutput,
    stopped: bool,
    after_stop: Arc<AtomicU64>,
}

impl ParserOutput for Watch<'_> {
    fn emit(&mut self, record: ForensicResult<ForensicData>) -> OutputFlow {
        if self.stopped {
            self.after_stop.fetch_add(1, Ordering::Relaxed);
            return OutputFlow::Stop;
        }
        let flow = self.out.emit(record);
        if flow == OutputFlow::Stop {
            self.stopped = true;
        }
        flow
    }
}

impl ReadinessMatrix {
    /// The matrix as a Markdown report.
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# ForensicRS pipeline readiness\n\n");
        s.push_str(&format!(
            "Generated by frnsc-pipeline {} over {} corpora: {}.\n\n",
            self.tool_version,
            self.corpora.len(),
            self.corpora.join(", ")
        ));
        s.push_str("| crate | parser | ready |");
        for c in CHECKS {
            s.push_str(&format!(" {c} |"));
        }
        s.push_str("\n|---|---|---|");
        for _ in CHECKS {
            s.push_str("---|");
        }
        s.push('\n');
        for p in &self.parsers {
            s.push_str(&format!(
                "| {} | `{}` | {} |",
                p.crate_name,
                p.parser,
                if p.ready() { "yes" } else { "**no**" }
            ));
            for c in CHECKS {
                s.push_str(&format!(
                    " {} |",
                    p.check(c).map_or("-", |r| r.outcome.symbol())
                ));
            }
            s.push('\n');
        }
        s.push_str("\n## Not pipeline-ready: no parser factory\n\n| crate | artifact | why |\n|---|---|---|\n");
        for g in &self.gaps {
            s.push_str(&format!(
                "| {} | {} | {} |\n",
                g.crate_name, g.artifact, g.reason
            ));
        }
        s.push_str("\n## Details\n");
        for p in &self.parsers {
            s.push_str(&format!("\n### `{}` ({})\n\n", p.parser, p.crate_name));
            for c in &p.checks {
                s.push_str(&format!(
                    "- **{}** {}: {}\n",
                    c.check,
                    c.outcome.symbol(),
                    c.detail.replace('\n', " ")
                ));
            }
        }
        s
    }
}
