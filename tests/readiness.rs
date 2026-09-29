//! The benchmark over the built-in corpora. It asserts what must hold for every parser (no
//! panic, no record from nothing) and pins the parsers known to be ready, so a regression shows
//! up here. A newly failing parser is a finding, not necessarily a bug in this crate.

use forensic_rs::prelude::{ParserDescriptor, Requirement};
use frnsc_pipeline::catalog::Catalog;
use frnsc_pipeline::fixtures;
use frnsc_pipeline::readiness::{self, benchmark, Outcome, CHECKS};

#[test]
fn every_parser_survives_empty_and_hostile_input() {
    let catalog = Catalog::standard();
    let matrix = benchmark(&catalog, &fixtures::standard(&catalog));
    assert_eq!(matrix.parsers.len(), catalog.parsers().count());
    for p in &matrix.parsers {
        assert_eq!(p.checks.len(), CHECKS.len(), "{}", p.parser);
        for check in ["empty", "garbage"] {
            let c = p.check(check).unwrap();
            assert_eq!(
                c.outcome,
                Outcome::Pass,
                "{} {check}: {}",
                p.parser,
                c.detail
            );
        }
    }
}

#[test]
fn parsers_with_fixtures_are_pipeline_ready() {
    let catalog = Catalog::standard();
    let matrix = benchmark(&catalog, &fixtures::standard(&catalog));
    for id in [
        "windows.ntfs.mft",
        "windows.ntfs.i30",
        "windows.ntfs.usnjrnl",
        "windows.ntfs.sds",
        "windows.registry.feature_usage",
        "windows.prefetch",
    ] {
        let p = matrix.parsers.iter().find(|p| p.parser == id).unwrap();
        for c in &p.checks {
            // `requirements` is Skip until the parsers name catalog definitions (roadmap
            // phase 4). A Fail there still has to show up here.
            if c.check == "requirements" {
                assert_ne!(c.outcome, Outcome::Fail, "{id} requirements: {}", c.detail);
                continue;
            }
            assert_eq!(c.outcome, Outcome::Pass, "{id} {}: {}", c.check, c.detail);
        }
    }
}

/// The check phase 3 exists for: a parser naming a definition the catalog doesn't have must
/// fail the benchmark, not run and quietly find nothing.
#[test]
fn a_requirement_the_catalog_does_not_have_fails() {
    let descriptor =
        ParserDescriptor::new("test.parser", "Test", "", "1.0").with_requirements(vec![
            Requirement::artifact("WindowsAMCacheHveFile"),
            Requirement::artifact("WindowsNotADefinition"),
        ]);
    let result = readiness::requirements_in(&descriptor, &frnsc_artifacts::CATALOG);
    assert_eq!(result.outcome, Outcome::Fail, "{}", result.detail);
    assert!(
        result.detail.contains("WindowsNotADefinition"),
        "{}",
        result.detail
    );
    assert!(
        !result.detail.contains("WindowsAMCacheHveFile"),
        "the known definition should not be reported: {}",
        result.detail
    );
}

#[test]
fn requirements_pass_for_definitions_the_catalog_has_under_any_of_their_names() {
    // `WindowsActiveDirectoryDatabase` is an alias, not a definition name: a parser may name
    // a definition either way.
    for name in [
        "WindowsAMCacheHveFile",
        "WindowsUserRegistryFiles",
        "WindowsActiveDirectoryDatabase",
    ] {
        let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0")
            .with_requirements(vec![Requirement::artifact(name)]);
        let result = readiness::requirements_in(&descriptor, &frnsc_artifacts::CATALOG);
        assert_eq!(result.outcome, Outcome::Pass, "{name}: {}", result.detail);
    }
}

/// Nothing declared means nothing checked. A pass here would be the silent one.
#[test]
fn a_parser_declaring_no_artifact_is_skipped_not_passed() {
    let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0");
    let result = readiness::requirements_in(&descriptor, &frnsc_artifacts::CATALOG);
    assert_eq!(result.outcome, Outcome::Skip, "{}", result.detail);
}

/// The check reads each corpus's own catalog, so a corpus with no catalog fails: a parser
/// declaring a definition there would resolve nothing and report nothing.
#[test]
fn a_corpus_carrying_no_catalog_fails() {
    let descriptor = ParserDescriptor::new("test.parser", "Test", "", "1.0")
        .with_requirements(vec![Requirement::artifact("WindowsAMCacheHveFile")]);
    let catalogless = fixtures::Corpus {
        name: "no-catalog".to_string(),
        kind: fixtures::CorpusKind::Empty,
        sources: forensic_rs::prelude::TriageSources::builder().build(),
    };
    let result = readiness::requirements(&descriptor, std::slice::from_ref(&catalogless));
    assert_eq!(result.outcome, Outcome::Fail, "{}", result.detail);
    assert!(result.detail.contains("no-catalog"), "{}", result.detail);

    // The same descriptor against the standard corpora, which do carry the catalog, passes —
    // so the Fail above is the missing catalog and not the requirement itself.
    let catalog = Catalog::standard();
    let ok = readiness::requirements(&descriptor, &fixtures::standard(&catalog));
    assert_eq!(ok.outcome, Outcome::Pass, "{}", ok.detail);
}

/// The unknown-definition rule on the function the benchmark actually calls. The same rule is
/// pinned on `requirements_in` above, but nothing in the product calls that one: without this
/// test, deleting the unknown-name branch from `requirements` would leave the suite green.
#[test]
fn a_requirement_the_corpus_catalog_does_not_have_fails() {
    let descriptor =
        ParserDescriptor::new("test.parser", "Test", "", "1.0").with_requirements(vec![
            Requirement::artifact("WindowsAMCacheHveFile"),
            Requirement::artifact("WindowsNotADefinition"),
        ]);
    let catalog = Catalog::standard();
    let corpora = fixtures::standard(&catalog);
    let result = readiness::requirements(&descriptor, &corpora);
    assert_eq!(result.outcome, Outcome::Fail, "{}", result.detail);
    assert!(
        result.detail.contains("WindowsNotADefinition"),
        "the unresolvable definition should be named: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("WindowsAMCacheHveFile"),
        "the known definition should not be reported: {}",
        result.detail
    );
    // Every corpus carries the catalog, so every one of them reports the same problem, each
    // named — a failure here is a property of the descriptor, not of one fixture.
    for corpus in &corpora {
        assert!(
            result.detail.contains(&corpus.name),
            "{} should be named: {}",
            corpus.name,
            result.detail
        );
    }
}

/// A parser resolves its definitions through the catalog the source carries, so every source
/// the pipeline builds must have one.
#[test]
fn every_evidence_source_carries_the_artifact_catalog() {
    let catalog = Catalog::standard();
    let base: std::sync::Arc<dyn forensic_rs::prelude::FileSystem> = std::sync::Arc::new(
        forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new()
            .with_file("disk.raw", fixtures::disk_image()),
    );
    let ev = frnsc_pipeline::evidence::open_image_on(
        &base,
        "disk.raw",
        &catalog,
        forensic_rs::prelude::Acquisition::ImageRead,
    );
    assert!(!ev.sources.is_empty(), "no source from the synthetic disk");
    let resolver = std::sync::Arc::new(catalog.resolver(None));
    for source in &ev.sources {
        let sources = source.sources(&resolver);
        let kb = sources
            .catalog()
            .unwrap_or_else(|| panic!("{}: no artifact catalog", source.label));
        assert!(
            kb.get("WindowsAMCacheHveFile").is_some(),
            "{}: the catalog is not the ForensicArtifacts one",
            source.label
        );
    }
}

#[test]
fn report_lists_parsers_and_gaps() {
    let catalog = Catalog::standard();
    let matrix = benchmark(&catalog, &fixtures::standard(&catalog));
    let md = matrix.to_markdown();
    for (_, p) in catalog.parsers() {
        assert!(md.contains(&format!("`{}`", p.descriptor().id)));
    }
    for gap in ["frnsc-winevt", "frnsc-esedb"] {
        assert!(md.contains(gap), "{gap} missing from the report");
    }
    let json = serde_json::to_value(&matrix).unwrap();
    assert!(json["parsers"].as_array().is_some_and(|p| !p.is_empty()));
}
