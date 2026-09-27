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
