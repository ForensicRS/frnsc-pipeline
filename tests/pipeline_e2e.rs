//! The whole pipeline over a synthetic GPT disk: image -> partition -> NTFS -> parsers -> files.

mod common;

use std::sync::Arc;

use common::TempDir;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_pipeline::catalog::Catalog;
use frnsc_pipeline::evidence::{self, Evidence};
use frnsc_pipeline::fixtures::disk_image;
use frnsc_pipeline::run::{run, RunOptions};

fn disk() -> Evidence {
    let base: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("disk.raw", disk_image()));
    evidence::open_image_on(
        &base,
        "disk.raw",
        &Catalog::standard(),
        Acquisition::ImageRead,
    )
}

fn opts(dir: &std::path::Path, parallel: bool) -> RunOptions {
    RunOptions {
        out_dir: dir.to_path_buf(),
        host: "TEST-HOST".into(),
        parallel,
        workers: Some(2),
    }
}

fn read(dir: &std::path::Path, file: &str) -> String {
    std::fs::read_to_string(dir.join("00-disk.raw_p1").join(file)).unwrap()
}

#[test]
fn image_is_opened_down_to_its_ntfs_volume() {
    let ev = disk();
    assert!(ev.unmounted.is_empty(), "{:?}", ev.unmounted);
    let labels: Vec<_> = ev.sources.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["disk.raw/p1"]);
    assert!(ev.sources[0]
        .vfs
        .exists(FPath::new("Windows/System32/notepad.exe")));
    // No hives on this volume, so no registry: registry parsers skip instead of failing.
    assert!(ev.sources[0].registry.is_none());
}

#[test]
fn serial_run_writes_a_deterministic_timeline() {
    let catalog = Catalog::standard();
    let (a, b) = (TempDir::new("e2e-a"), TempDir::new("e2e-b"));
    let summary = run(&disk(), &catalog, &opts(a.path(), false)).unwrap();
    run(&disk(), &catalog, &opts(b.path(), false)).unwrap();

    let s = &summary.sources[0];
    assert_eq!(s.dir, "00-disk.raw_p1");
    assert!(
        s.parsers_run.contains(&"windows.ntfs.mft".to_string()),
        "{:?}",
        s.parsers_run
    );
    assert!(s
        .parsers_skipped
        .contains(&"windows.registry.feature_usage".to_string()));
    assert!(s.records > 0);
    assert!(summary
        .gaps
        .iter()
        .any(|g| g.crate_name == "frnsc-prefetch"));

    let timeline = read(a.path(), "timeline.jsonl");
    // The deleted tool is in the timeline, graded as deleted metadata.
    assert!(timeline.contains("mimi.exe"));
    for file in ["timeline.jsonl", "provenance.json", "findings.jsonl"] {
        assert_eq!(
            read(a.path(), file),
            read(b.path(), file),
            "{file} differs between runs"
        );
    }
    assert!(a.path().join("summary.json").exists());
}

#[test]
fn parallel_run_yields_the_same_records() {
    let catalog = Catalog::standard();
    let (s, p) = (TempDir::new("e2e-serial"), TempDir::new("e2e-parallel"));
    let serial = run(&disk(), &catalog, &opts(s.path(), false)).unwrap();
    let parallel = run(&disk(), &catalog, &opts(p.path(), true)).unwrap();
    assert_eq!(serial.sources[0].records, parallel.sources[0].records);

    // Provenance ids depend on completion order; the records themselves must not.
    let records = |dir: &std::path::Path| {
        let mut v: Vec<String> = read(dir, "timeline.jsonl")
            .lines()
            .map(|l| {
                let mut j: serde_json::Value = serde_json::from_str(l).unwrap();
                j.as_object_mut().unwrap().remove("provenance");
                j.to_string()
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(records(s.path()), records(p.path()));
}

#[test]
fn unmountable_image_is_reported_not_dropped() {
    let base: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("junk.img", vec![0x42; 64 * 1024]));
    let ev = evidence::open_image_on(
        &base,
        "junk.img",
        &Catalog::standard(),
        Acquisition::ImageRead,
    );
    assert!(ev.sources.is_empty());
    assert_eq!(ev.unmounted.len(), 1);
    assert_eq!(ev.unmounted[0].label, "junk.img");
}
