//! `catalog kb`: the KB coverage report over the real `frnsc-artifacts` catalog.
//!
//! The counts are pinned. They are the measurement the roadmap's phases are judged by, so a
//! change in either direction has to be a deliberate edit here, with a line in the status log.

use forensic_rs::catalog::{ArtifactCatalog, Os};
use forensic_rs::prelude::*;
use frnsc_pipeline::catalog::{Catalog, CatalogEntry, Component};
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
///
/// FOR-5 (2026-09-30) moved 7 definitions from gap/unmapped to parser: `frnsc_winevt::EvtxParserFactory`
/// declares the six `WindowsXMLEventLog*` names, `frnsc_esedb::srum::SrumParserFactory` declares
/// `WindowsSystemResourceUsageMonitorDatabaseFile`. Six of those seven were `Gap`;
/// `WindowsXMLEventLogTerminalServices` was `Unmapped` (`frnsc_artifacts::output_artifact` has no
/// `WindowsEvents` variant for it), and a declared requirement rescues a definition from
/// `Unmapped` same as from `Gap` — see `mapped_definitions_are_never_unmapped`.
///
/// FOR-28 (2026-09-30) moved 4 more definitions from unmapped to parser:
/// `frnsc_linux::unix::utmp::UtmpParserFactory` declares `LinuxLastlogFile`, `LinuxUtmpFiles`,
/// `LinuxWtmp` and `UnixUtmpFile`, and `frnsc_artifacts::output_artifact` now maps all four to
/// `Artifact::Linux(LinuxArtifacts::Utmp)`. All four were `Unmapped` (no Linux parser existed
/// before this), so `Gap` is unchanged.
///
/// FOR-27/FOR-29/FOR-33-ish and FOR-32 (2026-09-30, same heartbeat window) moved 44 more
/// definitions from unmapped to parser, all `Declared` — every one of the new `frnsc_linux`
/// parsers names its own definitions outright:
/// `log::syslog::SyslogParserFactory`, `log::audit::AuditParserFactory`,
/// `shell::ShellHistoryParserFactory` and `packages::PackagesParserFactory` (the text-log and
/// shell-history/package family), and FOR-32's config/state family —
/// `unix::accounts::AccountsParserFactory`, `unix::ssh::SshParserFactory`,
/// `schedule::ScheduleParserFactory`, `units::UnitsParserFactory` and
/// `identity::IdentityParserFactory`. `Gap` is unchanged: none of these definitions had an
/// `output_artifact` mapping with no parser before now, so none were ever `Gap`.
///
/// FOR-33's separate KB regeneration (`frnsc-artifacts` @ `bf9bded`) added 2 new upstream
/// definitions, both landing as `Unmapped` (bumping `DEFINITION_COUNT` 732 -> 734 without moving
/// the `Parser`/`Gap` counts on its own).
///
/// FOR-30 (2026-09-30) moves one more definition from unmapped to parser, `Declared`:
/// `journal::parser::JournalParserFactory` declares `LinuxSystemdJournalLogs`, now mapped to
/// `Artifact::Linux(LinuxArtifacts::Journal)`. `Gap` is unchanged, for the same reason as above.
///
/// FOR-33 (2026-10-01) moves 5 more definitions from unmapped to parser, `Declared`:
/// `containers::ContainersParserFactory` declares `DockerContainerConfig`,
/// `DockerContainerHostConfig`, `GKEDockerContainerLogs`, `KubernetesContainerLogSymlinks` and
/// `KubernetesKubeletPodLogs`. None of the five has an `output_artifact` mapping (no
/// `LinuxArtifacts` variant fits container logs yet — a public `forensic-rs` API shape change,
/// out of scope here), so `Gap` is unchanged and the five move straight from `Unmapped`.
///
/// Roadmap phase 4 (2026-10-01) adds 2 definitions and moves none between statuses. The KB
/// regeneration (`frnsc-artifacts` @ `86799d2`) adds the local `BraveBrowserHistoryDatabaseFile`
/// and `VivaldiBrowserHistoryDatabaseFile`, both mapped to `BrowserHistory` and declared by
/// `frnsc_sqlite`'s `BrowserHistoryParserFactory`, so both land as `Parser` (71 -> 73, 734 ->
/// 736). `Gap` and `Unmapped` are unchanged.
///
/// The same phase stops crediting a parser by inference once it names its definitions, so
/// `FirefoxHistory`, which only shared `BrowserHistory` with what `windows.browser_history`
/// reads, falls from `Parser` to `Gap` (73 -> 72 parser, 7 -> 8 gap; 72 + 8 + 656 = 736).
///
/// Roadmap phase 6 (2026-10-01): frnsc-winreg-activity's BAM, Run keys, Services and ShimCache
/// parsers declare `WindowsBackgroundActivityModeratorKeys`, `WindowsRunKeys`, `WindowsServices`
/// and `WindowsAppCompatCache`, all four mapped and so far gaps (72 -> 76 parser, 8 -> 4 gap;
/// 76 + 4 + 656 = 736). The four gaps left are Firefox history, the ActivitiesCache, UAL and
/// scheduled tasks. Then the MountedDevices and WordWheelQuery parsers, whose definitions were
/// unmapped: 76 -> 78 parser, 656 -> 654 unmapped (78 + 4 + 654 = 736).
///
/// Roadmap phase 7 (2026-10-01): frnsc-sqlite's `browser.firefox_history` declares
/// `FirefoxHistory`, a gap until now: 78 -> 79 parser, 4 -> 3 gap (79 + 3 + 654 = 736). Then
/// frnsc-esedb's `windows.ual` declares `WindowsUserAccessLogging`: 79 -> 80 parser, 3 -> 2 gap
/// (80 + 2 + 654 = 736). Then frnsc-sqlite's `windows.timeline` declares
/// `WindowsActivitiesCacheDatabase`: 80 -> 81 parser, 2 -> 1 gap (81 + 1 + 654 = 736). The one
/// gap left is scheduled tasks, whose definition spans two formats no crate reads yet.
#[test]
fn the_counts_are_pinned() {
    let report = report();
    let counts = report.counts();
    assert_eq!(
        counts.get(&Status::Parser),
        Some(&81),
        "{}",
        report.summary()
    );
    assert_eq!(counts.get(&Status::Gap), Some(&1), "{}", report.summary());
    assert_eq!(
        counts.get(&Status::Unmapped),
        Some(&654),
        "{}",
        report.summary()
    );
    // 387 definitions name Windows (385 upstream, plus the local Brave and Vivaldi ones), plus
    // the 3 that name no OS at all, which means every OS.
    assert_eq!(
        report
            .rows
            .iter()
            .filter(|r| r.supports(Os::Windows))
            .count(),
        390
    );
}

/// Every definition `frnsc-artifacts` maps to an `Artifact` is either covered or a gap. A
/// mapped definition falling into `unmapped` would mean the report lost it.
///
/// The converse does not hold: a parser can declare `Requirement::Artifact` for a definition
/// `frnsc-artifacts` has no `Artifact` mapping for (`WindowsXMLEventLogTerminalServices` — see
/// `frnsc_winevt::parser`'s own docs on why `WindowsEvents` has no variant for it), which rescues
/// it to `Parser` without ever being "mapped".
#[test]
fn mapped_definitions_are_never_unmapped() {
    for row in report().rows {
        let mapped = frnsc_artifacts::MAPPED_DEFINITIONS.contains(&row.definition.as_str());
        if mapped {
            assert_ne!(
                row.status,
                Status::Unmapped,
                "{}: mapped but reported unmapped",
                row.definition
            );
        }
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

/// Roadmap phase 4 made every covering parser in the standard catalog name its definitions, so
/// no row is inferred any more: every `Parser` row is `Declared`, by name or as a member of a
/// group a parser names (`linux.identity` declares `LinuxReleaseInfo`, which reaches
/// `LinuxLSBRelease`). A new parser that declares only an `Artifact` would bring inference
/// back, visibly, here.
#[test]
fn coverage_is_inferred_until_the_parsers_declare_their_definitions() {
    let report = report();
    assert_eq!(report.covering_counts().get("declared"), Some(&81));
    assert_eq!(report.covering_counts().get("inferred"), Some(&0));
    for row in report.rows.iter().filter(|r| r.status == Status::Parser) {
        assert_eq!(row.covering, Some(Covering::Declared), "{}", row.definition);
    }
    let lsb = report
        .rows
        .iter()
        .find(|r| r.definition == "LinuxLSBRelease")
        .unwrap();
    assert_eq!(lsb.parser, "linux.identity", "declared through its group");
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
        (
            "WindowsXMLEventLogSecurity",
            "evtx",
            "frnsc-winevt",
            "windows.evtx",
        ),
        (
            "WindowsSystemResourceUsageMonitorDatabaseFile",
            "esedb",
            "frnsc-esedb",
            "windows.srum",
        ),
        (
            "WindowsActivitiesCacheDatabase",
            "sqlite",
            "frnsc-sqlite",
            "windows.timeline",
        ),
    ] {
        let r = row(definition);
        assert_eq!((r.format, r.reader), (format, reader), "{definition}");
        assert_eq!(r.parser, parser, "{definition}");
        assert_eq!(r.status, Status::Parser, "{definition}");
    }
    // Nothing reads a format we have no crate for, and nothing is guessed from a path.
    assert_eq!(row("WindowsSearchDatabaseFile").format, "-");
    // A definition spanning two container formats names neither. `WindowsScheduledTasks` is
    // legacy `.job` binaries *and* task XML; claiming `job` would send a reader after the
    // smaller half of the artifact.
    let tasks = row("WindowsScheduledTasks");
    assert_eq!((tasks.format, tasks.reader), ("-", "-"));
    // The registry fallback applies only when every source is a registry kind. These two also
    // have file (and, for Crowdstrike, command) sources that `frnsc-hive` does not read.
    for definition in ["MicrosoftOfficeMRU", "CrowdstrikeAgentID"] {
        let r = row(definition);
        assert_eq!((r.format, r.reader), ("-", "-"), "{definition}");
        // The source kinds that were actually read are still reported.
        assert!(r.sources.contains("registry-value"), "{definition}");
        assert!(r.sources.contains("file"), "{definition}");
    }
}

/// The table must say whether a `parser` column is the parser's own declaration or this report's
/// inference. Without it, an inferred row reads as "this is parsed" when the report only guessed
/// it from a shared `Artifact` — `FirefoxHistory` did, until phase 4: frnsc-sqlite's
/// `windows.browser_history` declares the generic `BrowserHistory` artifact and reads only the
/// Chromium schema.
#[test]
fn an_inferred_row_is_marked_as_inferred_in_the_table() {
    let table = report().to_table();
    let line = |table: &str, name: &str| {
        table
            .lines()
            .find(|l| l.split_whitespace().last() == Some(name))
            .unwrap_or_else(|| panic!("{name} has no line"))
            .to_string()
    };
    // `windows.browser_history` names only Chromium definitions, so Firefox is credited to the
    // parser that declares it, `browser.firefox_history`, and nothing else.
    let firefox = line(&table, "FirefoxHistory");
    assert!(firefox.contains("declared"), "{firefox}");
    assert!(firefox.contains("browser.firefox_history"), "{firefox}");
    assert!(!firefox.contains("windows.browser_history"), "{firefox}");

    // A parser that names no definition, only an `Artifact`, is still credited by inference, and
    // the row says so.
    let only_artifact = Catalog::from_entries(vec![CatalogEntry {
        crate_name: "test",
        component: Component::Parser(std::sync::Arc::new(ArtifactOnlyParser::default())),
    }]);
    let inferred = KbReport::build(&only_artifact, &frnsc_artifacts::CATALOG).to_table();
    let firefox = line(&inferred, "FirefoxHistory");
    assert!(firefox.contains("inferred"), "{firefox}");
    assert!(firefox.contains("test.artifact_only"), "{firefox}");

    let line = |name: &str| line(&table, name);
    // A parser naming the definition itself (FOR-5's `windows.evtx`) is marked `declared`, not
    // `inferred`: the row is a fact the parser stated, not this report's guess.
    let evtx = line("WindowsXMLEventLogSecurity");
    assert!(evtx.contains("declared"), "{evtx}");
    assert!(!evtx.contains("inferred"), "{evtx}");
    // A gap is not marked either way.
    let gap = line("WindowsScheduledTasks");
    assert!(!gap.contains("inferred"), "{gap}");
    assert!(!gap.contains("declared"), "{gap}");

    // Every line has the same column count, so the table stays splittable: no value is ever
    // wide enough to shift the columns of its row.
    // No `with_source`, so the column header is the first line.
    let header = table.lines().next().unwrap_or_default();
    assert!(header.starts_with("status"), "{header}");
    let columns = header.split_whitespace().count();
    for l in table
        .lines()
        .skip(1)
        .take(frnsc_artifacts::DEFINITION_COUNT)
    {
        assert_eq!(l.split_whitespace().count(), columns, "{l}");
    }
}

/// `--os windows` keeps definitions that declare no OS at all, because the definition format
/// reads an empty `supported_os` as every OS. The row has to show that, or it reads as a claim
/// about Windows that the KB never made.
#[test]
fn a_definition_declaring_no_os_says_so() {
    let report = report();
    let row = |name: &str| {
        report
            .rows
            .iter()
            .find(|r| r.definition == name)
            .unwrap_or_else(|| panic!("{name} has no row"))
    };
    let any = row("LinuxCACertificatesConfiguration");
    assert!(any.supported_os.is_empty());
    assert!(
        any.supports(Os::Windows),
        "an empty supported_os is every OS"
    );
    assert_eq!(any.os_column(), "any");
    assert_eq!(row("WindowsPrefetchFiles").os_column(), "Windows");
    assert!(report.to_table().contains(" any "));
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
        table.contains("736 definitions: 81 parser, 1 gap, 654 unmapped"),
        "{}",
        table.lines().last().unwrap_or_default()
    );
    assert_eq!(
        table.lines().count(),
        frnsc_artifacts::DEFINITION_COUNT + 3,
        "one line per definition, plus the KB header, the column header and the counts"
    );
}

/// A parser that declares the `BrowserHistory` artifact and no definition.
struct ArtifactOnlyParser {
    descriptor: ParserDescriptor,
}

impl Default for ArtifactOnlyParser {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new("test.artifact_only", "test", "test", "0")
                .with_artifacts(vec![Artifact::Common(CommonArtifact::WebBrowsing(
                    WebBrowsingArtifact::BrowserHistory,
                ))]),
        }
    }
}

impl ArtifactParserFactory for ArtifactOnlyParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }
    fn can_parse(&self, _: &ParseContext<'_>) -> bool {
        false
    }
    fn open(&self, _: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        Ok(ParserRun::pull(std::iter::empty()))
    }
}
