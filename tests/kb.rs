//! `catalog kb`: the KB coverage report over the real `frnsc-artifacts` catalog.
//!
//! The counts are pinned. They are the measurement the roadmap's phases are judged by, so a
//! change in either direction has to be a deliberate edit here, with a line in the status log.

use forensic_rs::catalog::{ArtifactCatalog, Os};
use frnsc_pipeline::catalog::Catalog;
use frnsc_pipeline::kb::{Covering, KbReport, Status};

fn report() -> KbReport {
    KbReport::build(&Catalog::standard(), &frnsc_artifacts::CATALOG)
}

#[test]
fn every_definition_gets_exactly_one_row() {
    let report = report();
    assert_eq!(report.rows.len(), frnsc_artifacts::DEFINITION_COUNT);
    let counts = report.counts();
    assert_eq!(
        counts.values().sum::<usize>(),
        report.rows.len(),
        "every row must have exactly one status"
    );
    for definition in frnsc_artifacts::CATALOG.iter() {
        assert!(
            report.rows.iter().any(|r| r.definition == definition.name),
            "{} has no row",
            definition.name
        );
    }
}

/// `HashMap` order must never reach the output: the rows follow the catalog's name order.
#[test]
fn rows_are_sorted_by_definition_name() {
    let rows = report().rows;
    for pair in rows.windows(2) {
        assert!(
            pair[0].definition < pair[1].definition,
            "{} then {}",
            pair[0].definition,
            pair[1].definition
        );
    }
    assert_eq!(report().to_table(), report().to_table());
}

/// The counts the roadmap's phase 3 is measured by. The 2026-09-27 study report had 4 parser
/// and 11 gap over a 15-definition mapping; both deltas are accounted for in the status log:
/// `WindowsPrefetchFiles` gained a factory, `FirefoxHistory` is covered only by inference, and
/// `frnsc-artifacts`' mapping added the four registry definitions.
#[test]
fn the_counts_are_pinned() {
    let report = report();
    let counts = report.counts();
    assert_eq!(
        counts.get(&Status::Parser),
        Some(&6),
        "{}",
        report.summary()
    );
    assert_eq!(counts.get(&Status::Gap), Some(&13), "{}", report.summary());
    assert_eq!(
        counts.get(&Status::Unmapped),
        Some(&713),
        "{}",
        report.summary()
    );
    // 385 definitions name Windows, plus the 3 that name no OS at all, which means every OS.
    assert_eq!(
        report
            .rows
            .iter()
            .filter(|r| r.supports(Os::Windows))
            .count(),
        388
    );
}

/// Every definition `frnsc-artifacts` maps to an `Artifact` is either covered or a gap. A
/// mapped definition falling into `unmapped` would mean the report lost it.
#[test]
fn mapped_definitions_are_never_unmapped() {
    for row in report().rows {
        let mapped = frnsc_artifacts::MAPPED_DEFINITIONS.contains(&row.definition.as_str());
        assert_eq!(
            mapped,
            row.status != Status::Unmapped,
            "{}: mapped={mapped}, status={}",
            row.definition,
            row.status.as_str()
        );
        assert_eq!(mapped, row.artifact.is_some(), "{}", row.definition);
    }
}

/// A gap names no parser, and a covered definition always names one.
#[test]
fn the_parser_column_agrees_with_the_status() {
    for row in report().rows {
        match row.status {
            Status::Parser => {
                assert!(!row.parser.is_empty(), "{}", row.definition);
                assert!(row.covering.is_some(), "{}", row.definition);
            }
            Status::Gap | Status::Unmapped => {
                assert!(row.parser.is_empty(), "{}", row.definition);
                assert!(row.covering.is_none(), "{}", row.definition);
            }
        }
    }
}

/// Until roadmap phase 4, coverage is inferred from the output artifact. That is a heuristic,
/// and this pin is what makes its removal visible.
#[test]
fn coverage_is_inferred_until_the_parsers_declare_their_definitions() {
    let report = report();
    assert_eq!(report.covering_counts().get("declared"), Some(&0));
    assert_eq!(report.covering_counts().get("inferred"), Some(&6));
    for row in report.rows.iter().filter(|r| r.status == Status::Parser) {
        assert_eq!(row.covering, Some(Covering::Inferred), "{}", row.definition);
    }
}

#[test]
fn a_definition_names_the_crate_that_reads_its_format() {
    let report = report();
    let row = |name: &str| {
        report
            .rows
            .iter()
            .find(|r| r.definition == name)
            .unwrap_or_else(|| panic!("{name} has no row"))
    };
    for (definition, format, reader, parser) in [
        (
            "WindowsAMCacheHveFile",
            "regf",
            "frnsc-hive",
            "windows.amcache",
        ),
        (
            "WindowsPrefetchFiles",
            "scca",
            "frnsc-prefetch",
            "windows.prefetch",
        ),
        ("NTFSMFTFiles", "ntfs", "frnsc-ntfs", "windows.ntfs.mft"),
    ] {
        let r = row(definition);
        assert_eq!((r.format, r.reader), (format, reader), "{definition}");
        assert_eq!(r.parser, parser, "{definition}");
        assert_eq!(r.status, Status::Parser, "{definition}");
    }
    // A gap still names the crate that would host the factory.
    for (definition, format, reader) in [
        ("WindowsXMLEventLogSecurity", "evtx", "frnsc-winevt"),
        (
            "WindowsSystemResourceUsageMonitorDatabaseFile",
            "esedb",
            "frnsc-esedb",
        ),
        ("WindowsRunKeys", "regf", "frnsc-hive"),
    ] {
        let r = row(definition);
        assert_eq!((r.format, r.reader), (format, reader), "{definition}");
        assert_eq!(r.status, Status::Gap, "{definition}");
    }
    // Nothing reads a format we have no crate for, and nothing is guessed from a path.
    assert_eq!(row("WindowsScheduledTasks").reader, "-");
    assert_eq!(row("WindowsSearchDatabaseFile").format, "-");
}

#[test]
fn the_source_kinds_are_the_definitions_own() {
    let report = report();
    let sources = |name: &str| {
        report
            .rows
            .iter()
            .find(|r| r.definition == name)
            .map(|r| r.sources.clone())
            .unwrap_or_else(|| panic!("{name} has no row"))
    };
    assert_eq!(sources("WindowsPrefetchFiles"), "file");
    assert_eq!(sources("WindowsRunKeys"), "registry-key");
    assert_eq!(sources("WindowsAppCompatCache"), "registry-value");
    // An ARTIFACT_GROUP is reported as one, not flattened into its members' kinds.
    assert_eq!(sources("BrowserHistory"), "group");
    // Several kinds in one definition are all listed, sorted.
    assert_eq!(sources("MicrosoftOfficeMRU"), "file+registry-value");
}

#[test]
fn the_table_carries_the_kb_commit_and_the_counts() {
    let table = report()
        .with_source(format!(
            "{} @ {}",
            frnsc_artifacts::KB_REPO,
            frnsc_artifacts::KB_COMMIT
        ))
        .to_table();
    assert!(table.contains(frnsc_artifacts::KB_COMMIT), "{table:.200}");
    assert!(
        table.contains("732 definitions: 6 parser, 13 gap, 713 unmapped"),
        "{}",
        table.lines().last().unwrap_or_default()
    );
    assert_eq!(
        table.lines().count(),
        frnsc_artifacts::DEFINITION_COUNT + 3,
        "one line per definition, plus the KB header, the column header and the counts"
    );
}
