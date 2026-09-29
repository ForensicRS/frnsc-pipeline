//! `frnsc-pipeline`: run the whole ForensicRS pipeline over evidence, or benchmark its parsers.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use forensic_rs::catalog::Os;
use forensic_rs::prelude::*;
use frnsc_pipeline::catalog::Catalog;
use frnsc_pipeline::fixtures::{self, Corpus, CorpusKind};
use frnsc_pipeline::kb::{KbReport, Status};
use frnsc_pipeline::run::{self, RunOptions};
use frnsc_pipeline::{evidence, readiness};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run every parser over a collection folder or a disk image.
    Run {
        /// A triage folder rooted at the system drive, or a raw / split-raw disk image.
        #[arg(long)]
        input: PathBuf,
        /// Output directory (created if missing).
        #[arg(long)]
        out: PathBuf,
        /// Host name to stamp on every record.
        #[arg(long)]
        host: String,
        /// How the evidence was acquired. Default: image-read for an image, remote-collection
        /// for a folder.
        #[arg(long, value_enum)]
        acquisition: Option<AcquisitionArg>,
        /// Use the parallel pipeline (record order is then not deterministic).
        #[arg(long)]
        parallel: bool,
        #[arg(long)]
        workers: Option<usize>,
    },
    /// List every crate the pipeline uses: parsers, formats, backends and gaps.
    Catalog {
        #[command(subcommand)]
        what: Option<CatalogCommand>,
    },
    /// Benchmark every parser for pipeline readiness.
    Bench {
        /// Also run the checks over this evidence (folder or image; repeatable).
        #[arg(long)]
        evidence: Vec<PathBuf>,
        /// Write the Markdown report here (stdout when omitted).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also write the matrix as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Exit with status 1 when any parser fails a check.
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// One row per ForensicArtifacts definition: its format, the crate that reads it, the
    /// parser that covers it, and its status (parser / gap / unmapped).
    Kb {
        /// Only definitions with this status.
        #[arg(long, value_enum)]
        status: Option<StatusArg>,
        /// Only definitions that apply to this OS.
        #[arg(long, value_enum)]
        os: Option<OsArg>,
        /// Print only the counts line.
        #[arg(long)]
        summary: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum StatusArg {
    Parser,
    Gap,
    Unmapped,
}

impl From<StatusArg> for Status {
    fn from(s: StatusArg) -> Self {
        match s {
            StatusArg::Parser => Status::Parser,
            StatusArg::Gap => Status::Gap,
            StatusArg::Unmapped => Status::Unmapped,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum OsArg {
    Windows,
    Linux,
    Darwin,
    Esxi,
    Android,
    Ios,
}

impl From<OsArg> for Os {
    fn from(os: OsArg) -> Self {
        match os {
            OsArg::Windows => Os::Windows,
            OsArg::Linux => Os::Linux,
            OsArg::Darwin => Os::Darwin,
            OsArg::Esxi => Os::Esxi,
            OsArg::Android => Os::Android,
            OsArg::Ios => Os::Ios,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum AcquisitionArg {
    ImageRead,
    RemoteCollection,
    LiveApi,
    Memory,
}

impl From<AcquisitionArg> for Acquisition {
    fn from(a: AcquisitionArg) -> Self {
        match a {
            AcquisitionArg::ImageRead => Acquisition::ImageRead,
            AcquisitionArg::RemoteCollection => Acquisition::RemoteCollection,
            AcquisitionArg::LiveApi => Acquisition::LiveApi,
            AcquisitionArg::Memory => Acquisition::Memory,
        }
    }
}

fn main() -> ExitCode {
    match real_main(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main(cli: Cli) -> ForensicResult<ExitCode> {
    let catalog = Catalog::standard();
    match cli.command {
        Command::Catalog { what: None } => {
            for e in catalog.entries() {
                println!(
                    "{:<8} {:<22} {:<32} {}",
                    e.kind(),
                    e.crate_name,
                    e.name(),
                    e.detail()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Catalog {
            what:
                Some(CatalogCommand::Kb {
                    status,
                    os,
                    summary,
                }),
        } => {
            let mut report =
                KbReport::build(&catalog, &frnsc_artifacts::CATALOG).with_source(format!(
                    "{} @ {}",
                    frnsc_artifacts::KB_REPO,
                    frnsc_artifacts::KB_COMMIT
                ));
            if let Some(os) = os.map(Os::from) {
                report.rows.retain(|r| r.supports(os));
            }
            if let Some(status) = status.map(Status::from) {
                report.rows.retain(|r| r.status == status);
            }
            if summary {
                print!("{}", report.summary());
            } else {
                print!("{}", report.to_table());
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            input,
            out,
            host,
            acquisition,
            parallel,
            workers,
        } => {
            let ev = evidence::open(&input, &catalog, acquisition.map(Into::into))?;
            for u in &ev.unmounted {
                eprintln!("not mounted: {}: {}", u.label, u.reason);
            }
            if ev.sources.is_empty() {
                eprintln!("no source to run over");
                return Ok(ExitCode::FAILURE);
            }
            let summary = run::run(
                &ev,
                &catalog,
                &RunOptions {
                    out_dir: out.clone(),
                    host,
                    parallel,
                    workers,
                },
            )?;
            for s in &summary.sources {
                println!(
                    "{}: {} records, {} findings, {} errors, {} parsers run, {} skipped -> {}",
                    s.label,
                    s.records,
                    s.findings,
                    s.errors.len(),
                    s.parsers_run.len(),
                    s.parsers_skipped.len(),
                    out.join(&s.dir).display()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Bench {
            evidence: paths,
            out,
            json,
            strict,
        } => {
            let mut corpora = fixtures::standard(&catalog);
            for path in &paths {
                let ev = evidence::open(path, &catalog, None)?;
                for u in &ev.unmounted {
                    eprintln!("not mounted: {}: {}", u.label, u.reason);
                }
                let resolver = std::sync::Arc::new(catalog.resolver(None));
                for s in &ev.sources {
                    corpora.push(Corpus {
                        name: format!("evidence:{}", s.label),
                        kind: CorpusKind::External,
                        sources: s.sources(&resolver),
                    });
                }
            }
            let matrix = readiness::benchmark(&catalog, &corpora);
            let md = matrix.to_markdown();
            match out {
                Some(p) => std::fs::write(&p, md)?,
                None => print!("{md}"),
            }
            if let Some(p) = json {
                let text = serde_json::to_string_pretty(&matrix)
                    .map_err(|e| ForensicError::other("bench", e.to_string()))?;
                std::fs::write(p, text + "\n")?;
            }
            let failing = matrix.parsers.iter().filter(|p| !p.ready()).count();
            eprintln!(
                "{} parsers, {failing} not pipeline-ready, {} crates without a parser factory",
                matrix.parsers.len(),
                matrix.gaps.len()
            );
            Ok(if strict && failing > 0 {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}
