//! The benchmark over the built-in corpora. It asserts what must hold for every parser (no
//! panic, no record from nothing) and pins the parsers known to be ready, so a regression shows
//! up here. A newly failing parser is a finding, not necessarily a bug in this crate.

use frnsc_pipeline::catalog::Catalog;
use frnsc_pipeline::fixtures;
use frnsc_pipeline::readiness::{benchmark, Outcome, CHECKS};

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
    ] {
        let p = matrix.parsers.iter().find(|p| p.parser == id).unwrap();
        for c in &p.checks {
            assert_eq!(c.outcome, Outcome::Pass, "{id} {}: {}", c.check, c.detail);
        }
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
    for gap in ["frnsc-prefetch", "frnsc-winevt", "frnsc-esedb"] {
        assert!(md.contains(gap), "{gap} missing from the report");
    }
    let json = serde_json::to_value(&matrix).unwrap();
    assert!(json["parsers"].as_array().is_some_and(|p| !p.is_empty()));
}
