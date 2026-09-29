//! The ForensicArtifacts knowledge base seen from the pipeline: for every definition, what
//! reads its container format, which parser covers it, and whether a pipeline can use it.
//!
//! One row per definition of the catalog handed to [`KbReport::build`] — [`crate::evidence`]
//! attaches `frnsc-artifacts`, so that is 732 rows of the pinned KB commit. This replaces the
//! throwaway `classify.py` the 2026-09-27 study report was built with.
//!
//! A definition is covered by a parser in two ways, and the report keeps them apart because
//! only the first is authoritative:
//!
//! * [`Covering::Declared`] — a parser names the definition in
//!   [`Requirement::Artifact`](forensic_rs::prelude::Requirement::Artifact). That is the
//!   parser itself saying what it consumes.
//! * [`Covering::Inferred`] — no parser names it, but one declares the
//!   [`Artifact`] that [`frnsc_artifacts::output_artifact`] maps the definition to. This
//!   over-claims when several definitions map to one artifact: `FirefoxHistory` and
//!   `ChromiumBasedBrowsersHistoryDatabaseFile` both map to `BrowserHistory`, while
//!   frnsc-sqlite only reads the Chromium schema. Roadmap phase 4 replaces every inferred
//!   row with a declared one.
//!
//! Nothing here guesses: a definition with no mapping is [`Status::Unmapped`], not silently
//! folded into a gap.

use std::collections::BTreeMap;

use forensic_rs::artifact::{Artifact, CommonArtifact, WebBrowsingArtifact, WindowsArtifacts};
use forensic_rs::catalog::{ArtifactCatalog, ArtifactDefinition, ArtifactSource, Os};
use forensic_rs::prelude::*;

use crate::catalog::Catalog;

/// How the covering parser was established. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Covering {
    Declared,
    Inferred,
}

impl Covering {
    pub fn as_str(self) -> &'static str {
        match self {
            Covering::Declared => "declared",
            Covering::Inferred => "inferred",
        }
    }
}

/// How far a definition is from being usable in a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// A catalog parser covers it.
    Parser,
    /// It maps to an [`Artifact`] the ecosystem knows, but no parser factory covers it.
    Gap,
    /// No definition-to-artifact mapping, so the ecosystem has no counterpart for it.
    Unmapped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Parser => "parser",
            Status::Gap => "gap",
            Status::Unmapped => "unmapped",
        }
    }

    /// The three statuses, in report order.
    pub const ALL: [Status; 3] = [Status::Parser, Status::Gap, Status::Unmapped];
}

/// One KB definition, and what the pipeline can do with it.
pub struct KbRow {
    pub definition: String,
    /// The KB source kinds the definition uses (`file`, `registry-key`, ..), sorted and joined
    /// with `+`: what has to be read, before any format is known.
    pub sources: String,
    /// The container format the data is stored in, under the name
    /// `artifacts-kb/artifactsrc/formats.yaml` gives it (`regf`, `evtx`, `esedb`, ..), or `-`
    /// when the pipeline cannot tell. See [`format_of`].
    pub format: &'static str,
    /// The crate that reads [`Self::format`], or `-` when no crate does.
    pub reader: &'static str,
    /// The [`Artifact`] this definition is reported as, when
    /// [`frnsc_artifacts::output_artifact`] maps it.
    pub artifact: Option<Artifact>,
    /// The id of the parser that covers it, or `-`.
    pub parser: String,
    pub covering: Option<Covering>,
    pub status: Status,
    /// The definition's `supported_os`. Empty means every OS.
    pub supported_os: Vec<Os>,
}

impl KbRow {
    /// Whether the definition applies to `os` (an empty `supported_os` means every OS).
    pub fn supports(&self, os: Os) -> bool {
        self.supported_os.is_empty() || self.supported_os.contains(&os)
    }
}

/// The KB, row per definition, sorted by definition name.
pub struct KbReport {
    /// Where the definitions came from, for the report header.
    pub source: String,
    pub rows: Vec<KbRow>,
}

impl KbReport {
    /// Classifies every definition of `kb` against the parsers of `catalog`.
    pub fn build(catalog: &Catalog, kb: &dyn ArtifactCatalog) -> Self {
        let rows = kb.iter().map(|def| row(catalog, def)).collect();
        Self {
            source: String::new(),
            rows,
        }
    }

    /// Names the KB the rows came from (repo and commit), printed in the header.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// How many definitions are in each status, in [`Status::ALL`] order.
    pub fn counts(&self) -> BTreeMap<Status, usize> {
        let mut counts: BTreeMap<Status, usize> = Status::ALL.into_iter().map(|s| (s, 0)).collect();
        for row in &self.rows {
            *counts.entry(row.status).or_insert(0) += 1;
        }
        counts
    }

    /// How many covered definitions were established each way.
    pub fn covering_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::from([("declared", 0), ("inferred", 0)]);
        for row in self.rows.iter().filter_map(|r| r.covering) {
            *counts.entry(row.as_str()).or_insert(0) += 1;
        }
        counts
    }

    /// One line per definition, plus a header and the counts. Deterministic: the rows keep the
    /// catalog's name order and the counts come from a [`BTreeMap`].
    pub fn to_table(&self) -> String {
        let mut s = String::new();
        if !self.source.is_empty() {
            s.push_str(&format!("# ForensicArtifacts {}\n", self.source));
        }
        s.push_str(&format!(
            "{:<9} {:<9} {:<16} {:<32} {:<14} {}\n",
            "status", "format", "reader", "parser", "sources", "definition"
        ));
        for r in &self.rows {
            s.push_str(&format!(
                "{:<9} {:<9} {:<16} {:<32} {:<14} {}\n",
                r.status.as_str(),
                r.format,
                r.reader,
                if r.parser.is_empty() { "-" } else { &r.parser },
                r.sources,
                r.definition,
            ));
        }
        s.push_str(&self.summary());
        s
    }

    /// The counts line the roadmap's "reproduces the report's counts" is about.
    pub fn summary(&self) -> String {
        let counts = self.counts();
        let by_status = Status::ALL
            .into_iter()
            .map(|s| format!("{} {}", counts.get(&s).copied().unwrap_or(0), s.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let covering = self.covering_counts();
        format!(
            "{} definitions: {by_status} ({} declared, {} inferred)\n",
            self.rows.len(),
            covering.get("declared").copied().unwrap_or(0),
            covering.get("inferred").copied().unwrap_or(0),
        )
    }
}

fn row(catalog: &Catalog, def: &ArtifactDefinition) -> KbRow {
    let artifact = frnsc_artifacts::output_artifact(def.name.as_ref());
    let covered = covering_parser(catalog, def, artifact.as_ref());
    let (format, reader) = format_of(def, artifact.as_ref());
    KbRow {
        definition: def.name.to_string(),
        sources: source_kinds(def),
        format,
        reader,
        parser: covered
            .as_ref()
            .map_or_else(String::new, |(id, _)| id.clone()),
        covering: covered.as_ref().map(|(_, how)| *how),
        status: match (&covered, &artifact) {
            (Some(_), _) => Status::Parser,
            (None, Some(_)) => Status::Gap,
            (None, None) => Status::Unmapped,
        },
        artifact,
        supported_os: def.supported_os.to_vec(),
    }
}

/// The definition's source kinds, sorted, deduplicated and joined with `+`.
fn source_kinds(def: &ArtifactDefinition) -> String {
    let mut kinds: Vec<&'static str> = def
        .sources
        .iter()
        .map(|entry| match entry.source {
            ArtifactSource::File { .. } => "file",
            ArtifactSource::Path { .. } => "path",
            ArtifactSource::RegistryKey { .. } => "registry-key",
            ArtifactSource::RegistryValue { .. } => "registry-value",
            ArtifactSource::Wmi { .. } => "wmi",
            ArtifactSource::Command { .. } => "command",
            ArtifactSource::Group { .. } => "group",
            // `ArtifactSource` is `#[non_exhaustive]`: a new source kind is reported as
            // unknown rather than silently counted as one of the above.
            _ => "other",
        })
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.is_empty() {
        "-".to_string()
    } else {
        kinds.join("+")
    }
}

/// The parser that covers `def`, and how that was established. Parsers are tried in catalog
/// order, declarations before inferences, so the answer does not depend on iteration order.
fn covering_parser(
    catalog: &Catalog,
    def: &ArtifactDefinition,
    artifact: Option<&Artifact>,
) -> Option<(String, Covering)> {
    for (_, parser) in catalog.parsers() {
        let descriptor = parser.descriptor();
        let declared = descriptor.requirements.iter().any(|req| match req {
            Requirement::Artifact(a) => names(def).any(|name| name == a.name.as_ref()),
            _ => false,
        });
        if declared {
            return Some((descriptor.id.to_string(), Covering::Declared));
        }
    }
    let artifact = artifact?;
    for (_, parser) in catalog.parsers() {
        let descriptor = parser.descriptor();
        // `ParserDescriptor::handles` reads an empty `artifacts` as "every artifact". That is
        // the right default for dispatch, but it is not coverage of this definition.
        if !descriptor.artifacts.is_empty() && descriptor.artifacts.contains(artifact) {
            return Some((descriptor.id.to_string(), Covering::Inferred));
        }
    }
    None
}

/// The definition's name and every alias it answers to.
fn names(def: &ArtifactDefinition) -> impl Iterator<Item = &str> {
    std::iter::once(def.name.as_ref()).chain(def.aliases.iter().map(|a| a.as_ref()))
}

/// The container format `def`'s data is stored in, and the crate that reads that format.
///
/// The KB carries no format field — `artifacts-kb` keeps that in `artifactsrc/data/checks.yaml`,
/// for 33 of the 732 definitions, and the pipeline reads no files at run time. So this is
/// derived from two things we do know: the artifact the definition is reported as, and whether
/// it has registry sources. Anything else is `-`; a format is never guessed from a path.
pub fn format_of(
    def: &ArtifactDefinition,
    artifact: Option<&Artifact>,
) -> (&'static str, &'static str) {
    use WindowsArtifacts as W;
    let by_artifact = match artifact {
        Some(Artifact::Windows(W::MFT | W::UsnJrnl | W::I30 | W::Secure)) => {
            Some(("ntfs", "frnsc-ntfs"))
        }
        Some(Artifact::Windows(W::Registry(_))) => Some(("regf", "frnsc-hive")),
        Some(Artifact::Windows(W::Prefetch)) => Some(("scca", "frnsc-prefetch")),
        Some(Artifact::Windows(W::WinEvt(_))) => Some(("evtx", "frnsc-winevt")),
        Some(Artifact::Windows(W::SRU | W::UAL)) => Some(("esedb", "frnsc-esedb")),
        Some(Artifact::Windows(W::Timeline)) => Some(("sqlite", "frnsc-sqlite")),
        Some(Artifact::Common(CommonArtifact::WebBrowsing(
            WebBrowsingArtifact::BrowserHistory,
        ))) => Some(("sqlite", "frnsc-sqlite")),
        // `.job` and task XML: the KB names the format, no crate reads it (FINDINGS, phase 9).
        Some(Artifact::Windows(W::ScheduledTasks)) => Some(("job", "-")),
        _ => None,
    };
    if let Some(pair) = by_artifact {
        return pair;
    }
    let registry = def.sources.iter().any(|entry| {
        matches!(
            entry.source,
            ArtifactSource::RegistryKey { .. } | ArtifactSource::RegistryValue { .. }
        )
    });
    if registry {
        ("regf", "frnsc-hive")
    } else {
        ("-", "-")
    }
}

/// The `Requirement::Artifact` names in `descriptor` that `kb` does not have, sorted.
///
/// A parser that declares a definition the run's catalog cannot resolve would silently parse
/// nothing, so the readiness benchmark fails on a non-empty result here.
pub fn unknown_artifact_requirements(
    descriptor: &ParserDescriptor,
    kb: &dyn ArtifactCatalog,
) -> Vec<String> {
    let mut unknown: Vec<String> = artifact_requirements(descriptor)
        .filter(|name| kb.get(name).is_none())
        .map(str::to_string)
        .collect();
    unknown.sort();
    unknown.dedup();
    unknown
}

/// Every definition name `descriptor` declares as a `Requirement::Artifact`.
pub fn artifact_requirements(descriptor: &ParserDescriptor) -> impl Iterator<Item = &str> {
    descriptor.requirements.iter().filter_map(|req| match req {
        Requirement::Artifact(a) => Some(a.name.as_ref()),
        _ => None,
    })
}
