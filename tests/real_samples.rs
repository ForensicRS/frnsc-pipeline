//! The pipeline and the benchmark over real samples from the shared corpus. Skipped when the
//! samples are not fetched (`forensic-testenv/tools/fetch.py --crate frnsc-pipeline`), failing
//! under `FORENSIC_TESTDATA_STRICT=1`.
//!
//! The samples come from different machines. They are laid out as one drive-rooted collection
//! only to exercise every parser at once: the correlator's findings over it mean nothing.

mod common;

use std::path::{Path, PathBuf};

use common::TempDir;
use forensic_rs::prelude::{FPath, FileSystemExt};
use forensic_testdata::artifact_or_skip;
use frnsc_pipeline::catalog::Catalog;
use frnsc_pipeline::evidence;
use frnsc_pipeline::fixtures::{self, Corpus, CorpusKind};
use frnsc_pipeline::readiness::{benchmark, Outcome};
use frnsc_pipeline::run::{run, RunOptions};

fn place(root: &Path, rel: &str, sample: &Path) {
    let dest = root.join(rel);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::copy(sample, dest).unwrap();
}

/// The samples a collection is built from (`artifact_or_skip!` returns from the test itself).
macro_rules! collection_samples {
    () => {
        Samples {
            mft: artifact_or_skip!("ntfs-mkntfs-mft"),
            system: artifact_or_skip!("hive-system-plaso"),
            amcache: artifact_or_skip!("hive-amcache-win10"),
            history: artifact_or_skip!("sqlite-chrome-history-synthetic"),
        }
    };
}

struct Samples {
    mft: PathBuf,
    system: PathBuf,
    amcache: PathBuf,
    history: PathBuf,
}

/// `C/` with `$MFT`, a SYSTEM hive, Amcache and a Chrome History.
fn collection(
    tmp: &TempDir,
    Samples {
        mft,
        system,
        amcache,
        history,
    }: Samples,
) -> PathBuf {
    let c = tmp.path().join("C");
    place(&c, "$MFT", &mft);
    place(&c, "Windows/System32/Config/SYSTEM", &system);
    place(&c, "Windows/AppCompat/Programs/Amcache.hve", &amcache);
    place(
        &c,
        "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History",
        &history,
    );
    c
}

#[test]
fn collection_folder_runs_every_file_parser() {
    let tmp = TempDir::new("real-collection");
    let c = collection(&tmp, collection_samples!());
    let catalog = Catalog::standard();
    let ev = evidence::open(&c, &catalog, None).unwrap();
    assert_eq!(ev.sources.len(), 1);
    assert!(
        ev.sources[0].registry.is_some(),
        "SYSTEM hive should give the source a registry"
    );

    let out = tmp.path().join("out");
    let summary = run(
        &ev,
        &catalog,
        &RunOptions {
            out_dir: out.clone(),
            host: "SAMPLES".into(),
            parallel: false,
            workers: None,
        },
    )
    .unwrap();
    let s = &summary.sources[0];
    for id in [
        "windows.ntfs.mft",
        "windows.amcache",
        "windows.browser_history",
    ] {
        assert!(
            s.parsers_run.iter().any(|p| p == id),
            "{id} did not run: {:?}",
            s.parsers_skipped
        );
    }
    let timeline = std::fs::read_to_string(out.join(&s.dir).join("timeline.jsonl")).unwrap();
    let count = |needle: &str| timeline.lines().filter(|l| l.contains(needle)).count();
    // Ground truth of the synthetic History: 5 URLs and 6 visits.
    assert_eq!(count("\"Common::WebBrowsing::BrowserHistory\""), 11);
    assert!(count("\"InventoryApplicationFile\"") > 0);
    assert!(count("\"mft_entry\"") > 0);
}

/// The same samples laid out like a Brimor Labs triage collection: nothing where a Windows
/// volume keeps it, hives and `$MFT` found by name.
#[test]
fn triage_collection_layout_is_found_by_name() {
    let Samples {
        mft,
        system,
        amcache,
        history: _,
    } = collection_samples!();
    let tmp = TempDir::new("real-triage");
    let root = tmp.path().join("collection");
    place(&root, "HOST/CopiedFiles/registry/SYSTEM", &system);
    place(&root, "HOST/CopiedFiles/Amcache.hve", &amcache);
    place(&root, "HOST/CopiedFiles/ntfs/$MFT.bin", &mft);
    let catalog = Catalog::standard();
    let ev = evidence::open(&root, &catalog, None).unwrap();
    assert_eq!(ev.sources.len(), 1);
    assert!(
        ev.sources[0].registry.is_some(),
        "SYSTEM should be found by name"
    );

    let out = tmp.path().join("out");
    let summary = run(
        &ev,
        &catalog,
        &RunOptions {
            out_dir: out.clone(),
            host: "SAMPLES".into(),
            parallel: false,
            workers: None,
        },
    )
    .unwrap();
    let s = &summary.sources[0];
    for id in ["windows.ntfs.mft", "windows.amcache"] {
        assert!(
            s.parsers_run.iter().any(|p| p == id),
            "{id} did not run: {:?}",
            s.parsers_skipped
        );
    }
    let timeline = std::fs::read_to_string(out.join(&s.dir).join("timeline.jsonl")).unwrap();
    assert!(timeline
        .lines()
        .any(|l| l.contains("\"InventoryApplicationFile\"")));
    assert!(timeline.lines().any(|l| l.contains("\"mft_entry\"")));
}

#[test]
fn bare_ntfs_volume_image_is_one_source() {
    let volume = artifact_or_skip!("ntfs-mkntfs-volume");
    let ev = evidence::open(&volume, &Catalog::standard(), None).unwrap();
    assert!(ev.unmounted.is_empty(), "{:?}", ev.unmounted);
    assert_eq!(ev.sources.len(), 1);
    assert!(ev.sources[0]
        .vfs
        .exists(FPath::new("Users/bob/Documents/small.txt")));
}

#[test]
fn every_parser_is_ready_on_real_samples() {
    let tmp = TempDir::new("real-bench");
    let c = collection(&tmp, collection_samples!());
    let volume = artifact_or_skip!("ntfs-mkntfs-volume");
    let catalog = Catalog::standard();
    let resolver = std::sync::Arc::new(catalog.resolver(None));
    let mut corpora = fixtures::standard(&catalog);
    for path in [c.as_path(), volume.as_path()] {
        for s in evidence::open(path, &catalog, None).unwrap().sources {
            corpora.push(Corpus {
                name: s.label.clone(),
                kind: CorpusKind::External,
                sources: s.sources(&resolver),
            });
        }
    }
    let matrix = benchmark(&catalog, &corpora);
    for p in &matrix.parsers {
        for c in &p.checks {
            // The inventory parser is a known wildcard (FINDINGS.md); everything else must pass
            // or, for record-hungry checks on a parser no sample feeds, skip.
            if p.parser == "core.container_inventory" {
                continue;
            }
            assert_ne!(
                c.outcome,
                Outcome::Fail,
                "{} {}: {}",
                p.parser,
                c.check,
                c.detail
            );
        }
    }
    for id in [
        "windows.amcache",
        "windows.browser_history",
        "windows.ntfs.mft",
    ] {
        let p = matrix.parsers.iter().find(|p| p.parser == id).unwrap();
        assert_eq!(p.check("coverage").unwrap().outcome, Outcome::Pass, "{id}");
    }
}

/// A real SYSTEM hive is reachable the way Windows and the ForensicArtifacts KB spell its paths:
/// under `HKLM\SYSTEM` in any case, with `CurrentControlSet` resolved through `Select\Current`
/// (an offline hive has no such key). Every SYSTEM-hive read failed before frnsc-hive stripped
/// the hive name for SYSTEM as it already did for SOFTWARE.
#[test]
fn a_real_system_hive_is_read_through_hklm_and_current_control_set() {
    use forensic_rs::prelude::{RegistryExt, StdVirtualFS};
    let system = artifact_or_skip!("hive-system-plaso");
    let tmp = TempDir::new("system-hive");
    let c = tmp.path().join("C");
    place(&c, "Windows/System32/Config/SYSTEM", &system);
    let fs: std::sync::Arc<dyn forensic_rs::prelude::FileSystem> =
        std::sync::Arc::new(forensic_rs::prelude::ChRootFileSystem::new(
            c.to_str().unwrap(),
            std::sync::Arc::new(StdVirtualFS::new()),
        ));
    let (registry, _) = evidence::registry_from(&fs);
    let registry = registry.expect("the SYSTEM hive loads");

    let current = registry
        .value(r"HKLM\SYSTEM\Select", "Current")
        .unwrap()
        .as_dword()
        .unwrap();
    let control_set = format!(r"HKLM\SYSTEM\ControlSet{current:03}\Services");
    let names = |entries: Vec<forensic_rs::traits::registry::KeyEntry>| -> Vec<String> {
        entries.into_iter().map(|e| e.name).collect()
    };
    let by_number = names(registry.key(&control_set).unwrap().keys().unwrap());
    assert!(!by_number.is_empty());
    for path in [
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services",
        r"hklm\system\currentcontrolset\services",
    ] {
        let via_link = names(
            registry
                .key(path)
                .unwrap_or_else(|e| panic!("{path}: {e}"))
                .keys()
                .unwrap(),
        );
        assert_eq!(via_link, by_number, "{path}");
    }

    // `Services` holds subkeys and no values: listing its values is empty, not an error (the
    // reader used to dereference the unset values-list offset of every value-less key).
    let services = registry
        .key(r"HKLM\SYSTEM\CurrentControlSet\Services")
        .unwrap()
        .values()
        .unwrap();
    assert!(services.is_empty(), "{services:?}");
    // `Select` has values and no subkeys: a child of it is not found, not a cell error (the
    // reader used to follow its unset subkeys-list offset).
    let missing = registry.key(r"HKLM\SYSTEM\Select\NoSuchKey").unwrap_err();
    assert!(missing.is_registry_not_found(), "{missing:?}");
    // AppCompatCache is larger than one cell holds: a big-data record, reassembled. The reader
    // used to return the record's 12-byte header as the value.
    let cache = registry
        .value(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
            "AppCompatCache",
        )
        .unwrap();
    let forensic_rs::prelude::RegValue::Binary(cache) = cache else {
        panic!("{cache:?}");
    };
    assert_eq!(cache.len(), 56_256);
    assert_eq!(
        cache[..4],
        0xbadc_0fee_u32.to_le_bytes(),
        "the Windows 7 cache signature"
    );
    // ... and it decodes whole: every entry of a real Windows 7 (32-bit) cache, no error.
    let (format, entries) = frnsc_winreg_activity::shimcache::parse(&cache);
    assert_eq!(
        format,
        Some(frnsc_winreg_activity::shimcache::Format::Windows7_32)
    );
    assert_eq!(entries.len(), 330);
    assert!(entries.iter().all(Result::is_ok));
    // A REG_MULTI_SZ decodes to its strings (the reader returned Unknown { ty: 7 } before).
    let group_order = registry
        .value(
            r"HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder",
            "List",
        )
        .unwrap();
    let forensic_rs::prelude::RegValue::MultiSZ(groups) = group_order else {
        panic!("{group_order:?}");
    };
    assert!(groups.iter().any(|g| g == "System Reserved"), "{groups:?}");
    // Value names compare case-insensitively, as in Windows.
    assert_eq!(
        registry
            .value(r"HKLM\SYSTEM\Select", "current")
            .unwrap()
            .as_dword(),
        Some(current)
    );
}

/// plaso's real `places.sqlite` (Firefox, 2011): every place and visit reads, matching what
/// sqlite3 itself counts (92 places, 1 visit), and it has no download annotations.
#[test]
fn a_real_firefox_places_database_reads_whole() {
    use frnsc_sqlite::artifacts::firefox::{read_downloads, read_places, read_visits};
    let places = artifact_or_skip!("sqlite-firefox-places");
    let db = frnsc_sqlite::sqlite::db::SqliteDb::open(&places).unwrap();
    assert_eq!(read_places(&db).unwrap().len(), 92);
    let visits = read_visits(&db).unwrap();
    assert_eq!(visits.len(), 1);
    assert_eq!(visits[0].visit_type, Some(2));
    assert!(read_downloads(&db).unwrap().is_empty());
}

/// plaso's real User Access Logging pair (a Server 2019 DC, 2022): the clients' users, last
/// accesses and per-day counts read, which the ESE reader lost before it followed the real record
/// layout, and every date is a FILETIME, not the 1899 OLE reading of its bytes.
#[test]
fn a_real_ual_pair_reads_users_days_and_filetime_dates() {
    use forensic_rs::prelude::*;
    use forensic_rs::utils::testing::{collect_run, InMemoryVirtualFileSystem};
    let identity = artifact_or_skip!("esedb-ual-systemidentity");
    let clients = artifact_or_skip!("esedb-ual-guid");
    let fs = InMemoryVirtualFileSystem::new()
        .with_file(
            "Windows/System32/LogFiles/Sum/SystemIdentity.mdb",
            std::fs::read(identity).unwrap(),
        )
        .with_file(
            "Windows/System32/LogFiles/Sum/{C519A76A-D9B5-4F85-B667-5FAC08E0E1B4}.mdb",
            std::fs::read(clients).unwrap(),
        );
    let sources = TriageSources::builder()
        .vfs(std::sync::Arc::new(fs))
        .acquisition(Acquisition::ImageRead)
        .build();
    let triage = TriageContext::new("DC-1", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let items = collect_run(
        frnsc_esedb::ual::UalParserFactory::new()
            .open(&ctx)
            .unwrap(),
    )
    .unwrap();
    assert!(items.iter().all(Result::is_ok));
    let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
    let clients: Vec<&&ForensicData> = records
        .iter()
        .filter(|r| r.field_as_str("ual.table") == Some("CLIENTS"))
        .collect();
    assert_eq!(clients.len(), 14);
    // Every client has a user, a last access and its per-day counts.
    assert!(clients
        .iter()
        .all(|c| c.field("ual.last_access").is_some() && c.field("ual.daily_accesses").is_some()));
    let mut users: Vec<&str> = clients
        .iter()
        .map(|c| c.field_as_str("user.name").unwrap())
        .collect();
    users.sort_unstable();
    users.dedup();
    assert_eq!(users, [r"ual\dc-1$", r"ual\hunter", r"ual\xtof-wks$"]);
    let first = clients
        .iter()
        .find(|c| c.field_as_str("source.address") == Some("::1"))
        .unwrap();
    assert_eq!(first.field_as_u64("ual.total_accesses"), Some(62));
    assert_eq!(
        first.field("ual.daily_accesses"),
        Some(&Field::Array(vec![Text::Borrowed("197:62")]))
    );
    assert_eq!(
        first.field_as_str("ual.role_name"),
        Some("Active Directory Domain Services")
    );
    for r in &records {
        if let Some(ts) = r.field_as_date("@timestamp") {
            assert_eq!(ts.year(), 2022, "{r:?}");
        }
    }
}

/// The real SRUDB.dat: NULL fixed columns are absent, never ESE's 0x2A filler read as a value
/// (the reader ignored the null bitmap, and App Timeline reported 0x2A2A2A2A2A2A2A2A as
/// in-focus time), and the id map still resolves every identity.
#[test]
fn a_real_srum_database_has_no_null_filler_values() {
    let path = artifact_or_skip!("esedb-srudb");
    let db = frnsc_esedb::EseDb::open(&path).unwrap();
    let timeline = db.table("{5C8CF1C7-7257-4F13-B223-970EF5939312}").unwrap();
    let filler = [0x2A2A_2A2A_2A2A_2A2A_i64, 0x2A2A_2A2A];
    let mut values = 0;
    for row in timeline.iter_rows() {
        for (_, value) in row.iter() {
            if let Some(v) = value.as_i64() {
                values += 1;
                assert!(!filler.contains(&v), "NULL filler read as a value: {v:#x}");
            }
        }
    }
    assert!(values > 0);
    let srum =
        frnsc_esedb::srum::SrumDatabase::from_db(frnsc_esedb::EseDb::open(&path).unwrap()).unwrap();
    assert_eq!(srum.index.app.len(), 2222);
    assert_eq!(srum.index.user.len(), 3671);
}
