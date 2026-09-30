//! Why a parser did not run.
//!
//! [`ArtifactParserFactory::can_parse`](forensic_rs::prelude::ArtifactParserFactory::can_parse)
//! returns a bare `bool`, and [`forensic_rs::pipeline::PipelineResult::parsers_skipped`] is a
//! bare `Vec<String>` of ids — both collapse several very different situations into one. A
//! source that never got an [`forensic_rs::catalog::ArtifactCatalog`] attached (a misconfigured
//! run) and a source whose catalog correctly resolved a declared definition to nothing (a
//! genuinely empty, correct run) look identical downstream.
//!
//! [`classify`] recomputes the real reason from what
//! [`ParseContext::resolve_artifact`](forensic_rs::prelude::ParseContext::resolve_artifact)
//! itself already distinguishes — no forensic-rs change, just examining what a skipped parser's
//! descriptor and the run's sources say instead of trusting the collapsed `bool`.

use forensic_rs::prelude::*;
use serde::Serialize;

use crate::kb;

/// Why one parser did not run against one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The parser declares `Requirement::Artifact`, but this source carries no artifact
    /// catalog at all. A misconfigured run, not an empty one.
    NoCatalog,
    /// A catalog is attached, but it does not know one of the parser's declared definitions.
    UnknownDefinition,
    /// Every declared definition resolved against the evidence and found nothing, with no read
    /// errors: a genuinely empty, correct result.
    ArtifactAbsent,
    /// Resolving a declared definition hit a read error (an unreadable directory, or a
    /// registry key/value that exists but can't be read).
    ResolveErrors,
    /// Not further classifiable from a `Requirement::Artifact` declaration: the parser declares
    /// none (its own `can_parse` logic decided on something this module cannot see, e.g. no
    /// filesystem attached), or its declared definitions did resolve yet it declined anyway.
    Declined,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::NoCatalog => "no_catalog",
            SkipReason::UnknownDefinition => "unknown_definition",
            SkipReason::ArtifactAbsent => "artifact_absent",
            SkipReason::ResolveErrors => "resolve_errors",
            SkipReason::Declined => "declined",
        }
    }
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One parser that did not run, and the classified reason.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedParser {
    pub parser: String,
    pub reason: SkipReason,
    pub detail: String,
}

/// Recomputes why `descriptor` did not run against `sources`, from its declared
/// `Requirement::Artifact` list — the same information `can_parse` had, examined instead of
/// collapsed into a bool.
///
/// Meant to be called on a parser that is already known to have been skipped (`can_parse`
/// returned `false`, or `open` failed). Checked in the same order `can_parse` implementations
/// in this workspace check them (see `frnsc-winevt`/`frnsc-esedb`'s `can_parse`): a missing
/// filesystem before a missing catalog, because with no filesystem at all a missing catalog is
/// not the interesting fact.
pub fn classify(descriptor: &ParserDescriptor, sources: &TriageSources) -> (SkipReason, String) {
    let declared: Vec<&str> = kb::artifact_requirements(descriptor).collect();
    if declared.is_empty() {
        return (
            SkipReason::Declined,
            "declares no Requirement::Artifact; can_parse() declined for a reason local to \
             the parser"
                .into(),
        );
    }
    if sources.vfs().is_none() {
        return (
            SkipReason::Declined,
            "no filesystem attached to this source".into(),
        );
    }
    let Some(catalog) = sources.catalog() else {
        return (
            SkipReason::NoCatalog,
            format!(
                "no artifact catalog attached; {} declared definition(s) unresolved: {}",
                declared.len(),
                declared.join(", ")
            ),
        );
    };
    let unknown = kb::unknown_artifact_requirements(descriptor, catalog.as_ref());
    if !unknown.is_empty() {
        return (
            SkipReason::UnknownDefinition,
            format!("catalog does not know: {}", unknown.join(", ")),
        );
    }

    let ctx = ParseContext::new(
        sources,
        &TriageContext::default(),
        &CancellationToken::new(),
    );
    let mut errors = Vec::new();
    let mut present = Vec::new();
    for name in &declared {
        match ctx.resolve_artifact(name) {
            Ok(res) if !res.errors.is_empty() => {
                errors.push(format!("{name}: {} read error(s)", res.errors.len()))
            }
            Ok(res) if !res.is_empty() => present.push(*name),
            Ok(_) => {}
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    if !errors.is_empty() {
        return (SkipReason::ResolveErrors, errors.join("; "));
    }
    if !present.is_empty() {
        return (
            SkipReason::Declined,
            format!(
                "{} resolved in the evidence, but can_parse() declined anyway",
                present.join(", ")
            ),
        );
    }
    (
        SkipReason::ArtifactAbsent,
        format!("not present in evidence: {}", declared.join(", ")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
    use std::sync::Arc;

    fn vfs_only_sources() -> TriageSources {
        TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .build()
    }

    /// The pin FOR-22 exists for: a hand-built catalog-less `TriageSources`, driven through a
    /// real `TriagePipeline` with a collecting sink, must classify as `no_catalog` — never
    /// `artifact_absent`. Confuse the two and a misconfigured run (no catalog wired up) reads
    /// as a clean, empty one.
    #[test]
    fn no_catalog_through_a_real_pipeline_run_classifies_as_no_catalog() {
        let sources = vfs_only_sources();
        let parser = frnsc_winevt::EvtxParserFactory::new();
        assert!(sources.catalog().is_none());

        let mut pipeline = TriagePipeline::builder()
            .context(TriageContext::new("HOST", "test"))
            .parser(Arc::new(parser))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let result = pipeline.run(&sources).unwrap();
        assert_eq!(result.parsers_run, Vec::<String>::new());
        assert_eq!(
            result.parsers_skipped,
            vec![frnsc_winevt::parser::PARSER_ID.to_string()]
        );

        let descriptor = frnsc_winevt::EvtxParserFactory::new().descriptor().clone();
        let (reason, detail) = classify(&descriptor, &sources);
        assert_eq!(reason, SkipReason::NoCatalog, "{detail}");
    }

    #[test]
    fn artifact_absent_when_the_catalog_has_nothing_for_it() {
        let sources = TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .catalog(frnsc_artifacts::catalog())
            .build();
        let parser = frnsc_winevt::EvtxParserFactory::new();
        let (reason, detail) = classify(parser.descriptor(), &sources);
        assert_eq!(reason, SkipReason::ArtifactAbsent, "{detail}");
    }

    #[test]
    fn unknown_definition_when_the_catalog_does_not_know_the_name() {
        let sources = TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .catalog(Arc::new(SliceCatalog::new(Vec::new()).unwrap()))
            .build();
        let parser = frnsc_winevt::EvtxParserFactory::new();
        let (reason, detail) = classify(parser.descriptor(), &sources);
        assert_eq!(reason, SkipReason::UnknownDefinition, "{detail}");
    }

    #[test]
    fn declined_when_the_parser_declares_no_requirement() {
        let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0");
        let (reason, _) = classify(&descriptor, &vfs_only_sources());
        assert_eq!(reason, SkipReason::Declined);
    }

    #[test]
    fn declined_when_there_is_no_filesystem_at_all() {
        let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0")
            .with_requirements(vec![Requirement::artifact("WindowsAMCacheHveFile")]);
        let sources = TriageSources::builder()
            .catalog(frnsc_artifacts::catalog())
            .build();
        let (reason, detail) = classify(&descriptor, &sources);
        assert_eq!(reason, SkipReason::Declined, "{detail}");
    }
}
