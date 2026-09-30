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

/// Whether `def` can only ever resolve through the registry under
/// [`ParseContext::resolve_artifact`](forensic_rs::prelude::ParseContext::resolve_artifact)'s own
/// OS choice (Windows when the definition supports it, else its first supported OS — see
/// `context.rs`'s `resolve_artifact`). A `.any()` over every source, ignoring `supported_os`,
/// over-fires on a definition like `WindowsEnvironmentVariableProgramFiles`: it has both a `Path`
/// and a `RegistryValue` source, both with an empty (every-OS) `supported_os`, so on Windows the
/// path source is just as reachable as the registry one and a missing registry must not be
/// blamed for it.
fn only_resolves_through_registry(def: &ArtifactDefinition) -> bool {
    let os = if def.supports(Os::Windows) {
        Os::Windows
    } else {
        def.supported_os.first().copied().unwrap_or(Os::Windows)
    };
    let mut applicable = def.sources.iter().filter(|s| s.supports(os)).peekable();
    applicable.peek().is_some()
        && applicable.all(|s| {
            matches!(
                s.source,
                ArtifactSource::RegistryKey { .. } | ArtifactSource::RegistryValue { .. }
            )
        })
}

/// Recomputes why `descriptor` did not run against `sources`, from its declared
/// `Requirement::Artifact` list — the same information `can_parse` had, examined instead of
/// collapsed into a bool.
///
/// Meant to be called on a parser that is already known to have been skipped (`can_parse`
/// returned `false`, or `open` failed). Checked in the same order `can_parse` implementations
/// in this workspace check them (see `frnsc-winevt`/`frnsc-esedb`'s `can_parse`): a missing
/// filesystem before a missing catalog, because with no filesystem at all a missing catalog is
/// not the interesting fact. A missing registry backend gets the same treatment, but only when a
/// declared definition actually needs one (`REGISTRY_KEY`/`REGISTRY_VALUE` sources) — unlike the
/// filesystem, most definitions in this catalog today are file-only, so a registry-less source is
/// the normal case and must not be blamed for them.
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

    // Mirrors the `vfs` guard above: a definition that can only resolve through the registry
    // (`REGISTRY_KEY`/`REGISTRY_VALUE`) looks identical to "genuinely absent" once resolved —
    // `resolve_expansion` records the missing backend as a note, not an error, and an
    // `ArtifactResolution` with nothing found either way has empty `files`/`keys`/`values`. Ask
    // first, the same way the vfs guard does, instead of trusting a result that cannot tell the
    // two apart.
    if sources.registry().is_none() {
        let needs_registry: Vec<&str> = declared
            .iter()
            .filter(|name| {
                catalog
                    .get(name)
                    .is_some_and(only_resolves_through_registry)
            })
            .copied()
            .collect();
        if !needs_registry.is_empty() {
            return (
                SkipReason::Declined,
                format!(
                    "no registry attached to this source; {} declared definition(s) can only \
                     resolve through the registry: {}",
                    needs_registry.len(),
                    needs_registry.join(", ")
                ),
            );
        }
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

    /// `WindowsActiveDesktop` (`frnsc-artifacts`) resolves only through `REGISTRY_KEY` sources,
    /// no file globs at all. With a filesystem attached but no registry, `resolve_artifact` would
    /// find nothing and no read error either — indistinguishable from "genuinely absent" unless
    /// `classify` asks about the missing backend first, the same way it already does for `vfs`.
    #[test]
    fn declined_when_a_registry_only_definition_has_no_registry_attached() {
        let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0")
            .with_requirements(vec![Requirement::artifact("WindowsActiveDesktop")]);
        let sources = TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .catalog(frnsc_artifacts::catalog())
            .build();
        assert!(sources.registry().is_none());
        let (reason, detail) = classify(&descriptor, &sources);
        assert_eq!(reason, SkipReason::Declined, "{detail}");
        assert!(detail.contains("no registry attached"), "{detail}");
    }

    /// A file-based definition must not be blamed for a missing registry it never needed: the
    /// registry guard only fires for declared definitions that actually have
    /// `REGISTRY_KEY`/`REGISTRY_VALUE` sources.
    #[test]
    fn artifact_absent_still_reachable_with_no_registry_for_a_file_only_definition() {
        let sources = TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .catalog(frnsc_artifacts::catalog())
            .build();
        assert!(sources.registry().is_none());
        let parser = frnsc_winevt::EvtxParserFactory::new();
        let (reason, detail) = classify(parser.descriptor(), &sources);
        assert_eq!(reason, SkipReason::ArtifactAbsent, "{detail}");
    }

    /// `WindowsEnvironmentVariableProgramFiles` (`frnsc-artifacts`) declares one `Path` source
    /// and one `RegistryValue` source, both with an empty (every-OS) `supported_os`: on Windows
    /// (the OS `resolve_artifact` picks for this definition) the path is just as reachable as
    /// the registry value. A registry guard that fires on "has *a* registry source" rather than
    /// "every OS-applicable source is a registry source" would wrongly decline this with no
    /// registry attached, even though the filesystem path could still resolve it.
    #[test]
    fn artifact_absent_still_reachable_with_no_registry_for_a_mixed_file_and_registry_definition()
    {
        let sources = TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .catalog(frnsc_artifacts::catalog())
            .build();
        assert!(sources.registry().is_none());
        let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0")
            .with_requirements(vec![Requirement::artifact(
                "WindowsEnvironmentVariableProgramFiles",
            )]);
        let (reason, detail) = classify(&descriptor, &sources);
        assert_eq!(reason, SkipReason::ArtifactAbsent, "{detail}");
    }

    /// `MicrosoftOfficeMRU` (`frnsc-artifacts`) declares a `Darwin`-only `File` source and a
    /// `Windows`-only `RegistryValue` source. `resolve_artifact` always resolves cross-platform
    /// definitions like this one for Windows (see `only_resolves_through_registry`'s doc comment
    /// and `context.rs`'s `resolve_artifact`), so the Darwin file source never applies through
    /// it: for this definition, "only resolves through the registry" is still the right call
    /// even though it also has a non-registry source overall.
    #[test]
    fn declined_when_a_registry_only_for_its_resolved_os_definition_has_no_registry_attached() {
        let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0")
            .with_requirements(vec![Requirement::artifact("MicrosoftOfficeMRU")]);
        let sources = TriageSources::builder()
            .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
            .catalog(frnsc_artifacts::catalog())
            .build();
        assert!(sources.registry().is_none());
        let (reason, detail) = classify(&descriptor, &sources);
        assert_eq!(reason, SkipReason::Declined, "{detail}");
        assert!(detail.contains("no registry attached"), "{detail}");
    }
}
