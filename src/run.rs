//! Runs every catalog parser over every evidence source and writes the results.
//!
//! Output layout (`<out>/`):
//!
//! ```text
//! summary.json                  what ran, what was skipped, errors, unmounted volumes, gaps
//! <source>/timeline.jsonl       one line per record, with its provenance id and confidence
//! <source>/provenance.json      the provenance side table those ids index into
//! <source>/findings.jsonl       findings: analyzers, anomaly tallies, parser failures, hive integrity
//! ```
//!
//! One directory per source: records of two volumes are never interleaved. The serial run is
//! deterministic (same input, byte-identical output); the parallel run writes records in
//! completion order.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use forensic_rs::prelude::*;
use serde::Serialize;

use crate::analyzers::ExecutionCorrelator;
use crate::catalog::{Catalog, Component};
use crate::evidence::{Evidence, EvidenceSource, Unmounted};

pub struct RunOptions {
    pub out_dir: PathBuf,
    /// Host name stamped on every record. It is analyst input: nothing here guesses it.
    pub host: String,
    pub parallel: bool,
    pub workers: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub host: String,
    pub mode: &'static str,
    pub sources: Vec<SourceSummary>,
    pub unmounted: Vec<Unmounted>,
    pub gaps: Vec<GapSummary>,
}

#[derive(Debug, Serialize)]
pub struct SourceSummary {
    pub label: String,
    /// Where the source is, hop by hop from the input.
    pub locator: String,
    pub dir: String,
    pub registry: bool,
    pub parsers_run: Vec<String>,
    pub parsers_skipped: Vec<String>,
    pub records: u64,
    pub findings: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GapSummary {
    #[serde(rename = "crate")]
    pub crate_name: &'static str,
    pub artifact: &'static str,
    pub reason: &'static str,
}

pub fn gaps(catalog: &Catalog) -> Vec<GapSummary> {
    catalog
        .entries()
        .iter()
        .filter_map(|e| match e.component {
            Component::Gap { artifact, reason } => Some(GapSummary {
                crate_name: e.crate_name,
                artifact,
                reason,
            }),
            _ => None,
        })
        .collect()
}

/// Runs the pipeline over every source in `evidence` and writes `opts.out_dir`.
pub fn run(
    evidence: &Evidence,
    catalog: &Catalog,
    opts: &RunOptions,
) -> ForensicResult<RunSummary> {
    fs::create_dir_all(&opts.out_dir)?;
    let resolver = Arc::new(catalog.resolver(None));
    let mut sources = Vec::with_capacity(evidence.sources.len());
    for (index, source) in evidence.sources.iter().enumerate() {
        let dir_name = format!("{index:02}-{}", slug(&source.label));
        let dir = opts.out_dir.join(&dir_name);
        fs::create_dir_all(&dir)?;
        let mut summary = if opts.parallel {
            run_parallel(source, catalog, &resolver, opts, &dir)?
        } else {
            run_serial(source, catalog, &resolver, opts, &dir)?
        };
        summary.dir = dir_name;
        sources.push(summary);
    }
    let summary = RunSummary {
        tool: env!("CARGO_PKG_NAME"),
        tool_version: env!("CARGO_PKG_VERSION"),
        host: opts.host.clone(),
        mode: if opts.parallel { "parallel" } else { "serial" },
        sources,
        unmounted: evidence.unmounted.clone(),
        gaps: gaps(catalog),
    };
    let mut w = BufWriter::new(File::create(opts.out_dir.join("summary.json"))?);
    serde_json::to_writer_pretty(&mut w, &summary)
        .map_err(|e| ForensicError::other("summary", e.to_string()))?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(summary)
}

struct Outputs {
    timeline: BufWriter<File>,
    provenance: BufWriter<File>,
    findings: BufWriter<File>,
}

/// Creates the per-source files. Findings raised while opening the source go first.
fn outputs(dir: &Path, source: &EvidenceSource) -> ForensicResult<Outputs> {
    let mut findings = BufWriter::new(File::create(dir.join("findings.jsonl"))?);
    for f in &source.findings {
        write_finding(&mut findings, f)?;
    }
    findings.flush()?;
    // The pipeline's finding sink appends after them.
    let findings = BufWriter::new(
        OpenOptions::new()
            .append(true)
            .open(dir.join("findings.jsonl"))?,
    );
    Ok(Outputs {
        timeline: BufWriter::new(File::create(dir.join("timeline.jsonl"))?),
        provenance: BufWriter::new(File::create(dir.join("provenance.json"))?),
        findings,
    })
}

fn write_finding(w: &mut impl Write, f: &Finding) -> ForensicResult<()> {
    serde_json::to_writer(&mut *w, f)
        .map_err(|e| ForensicError::other("findings", e.to_string()))?;
    w.write_all(b"\n")?;
    Ok(())
}

fn context(opts: &RunOptions) -> TriageContext {
    TriageContext::new(opts.host.clone(), "default")
}

fn run_serial(
    source: &EvidenceSource,
    catalog: &Catalog,
    resolver: &Arc<MountResolver>,
    opts: &RunOptions,
    dir: &Path,
) -> ForensicResult<SourceSummary> {
    let out = outputs(dir, source)?;
    let ctx = context(opts);
    let store = ctx.provenance_store();
    let registry = catalog.parser_registry()?;
    let mut pipeline = TriagePipeline::builder()
        .context(ctx)
        .parsers_from(&registry)
        .analyzer(Box::new(ExecutionCorrelator::new()))
        .sink(Box::new(
            ProvenanceJsonlSink::new(out.timeline, out.provenance, store).with_tool_version(
                concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
            ),
        ))
        .sink(Box::new(JsonlFindingSink::new(out.findings)))
        .on_parser_error(ErrorAction::Continue)
        .build()?;
    let result = pipeline.run(&source.sources(resolver))?;
    Ok(SourceSummary {
        label: source.label.clone(),
        locator: source.locator.to_string(),
        dir: String::new(),
        registry: source.registry.is_some(),
        parsers_run: result.parsers_run,
        parsers_skipped: result.parsers_skipped,
        records: result.items_processed,
        findings: result.findings_count + source.findings.len() as u64,
        errors: result.errors.iter().map(|e| e.to_string()).collect(),
    })
}

/// One task per parser, except the parsers the correlator needs: those run together in one
/// analysis module, because an analyzer only sees records of its own task.
fn run_parallel(
    source: &EvidenceSource,
    catalog: &Catalog,
    resolver: &Arc<MountResolver>,
    opts: &RunOptions,
    dir: &Path,
) -> ForensicResult<SourceSummary> {
    let out = outputs(dir, source)?;
    let ctx = context(opts);
    let store = ctx.provenance_store();
    let sources = source.sources(resolver);
    let correlator = ExecutionCorrelator::new();
    let wanted = correlator.supported_artifacts();

    let mut builder = ParallelPipeline::builder().context(ctx);
    if let Some(n) = opts.workers {
        builder = builder.workers(n);
    }
    let mut module =
        AnalysisModuleBuilder::new("execution_correlator").analyzer(Box::new(correlator));
    let mut names = Vec::new();
    for (_, parser) in catalog.parsers() {
        let id = parser.descriptor().id.to_string();
        names.push(id.clone());
        if wanted.iter().any(|a| parser.descriptor().handles(a)) {
            module = module.parser(Arc::clone(parser));
        } else {
            let s = sources.clone();
            let task = StandardParallelTaskBuilder::new(id)
                .parser(Arc::clone(parser))
                .sources(move || s)
                .on_error(ErrorAction::Continue)
                .build()?;
            builder = builder.task(Box::new(task));
        }
    }
    let s = sources.clone();
    builder = builder.module(
        module
            .sources(move || s)
            .on_error(ErrorAction::Continue)
            .build()?,
    );
    let mut pipeline = builder
        .sink(Box::new(
            ProvenanceJsonlSink::new(out.timeline, out.provenance, store).with_tool_version(
                concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
            ),
        ))
        .sink(Box::new(JsonlFindingSink::new(out.findings)))
        .build()?;
    let result = pipeline.run()?;
    Ok(SourceSummary {
        label: source.label.clone(),
        locator: source.locator.to_string(),
        dir: String::new(),
        registry: source.registry.is_some(),
        // The parallel result reports tasks, not parsers; list the parsers it was given.
        parsers_run: names,
        parsers_skipped: Vec::new(),
        records: result.items_processed,
        findings: result.findings_count + source.findings.len() as u64,
        errors: result
            .errors
            .iter()
            .map(|(task, e)| format!("{task}: {e}"))
            .collect(),
    })
}

/// `disk.raw/p1` -> `disk.raw_p1`: safe as a directory name, still recognizable.
fn slug(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches('_');
    let tail: String = s
        .chars()
        .rev()
        .take(60)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if tail.is_empty() {
        "source".into()
    } else {
        tail
    }
}
