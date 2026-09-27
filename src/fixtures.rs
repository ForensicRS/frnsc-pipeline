//! Inputs the readiness benchmark feeds every parser. Synthetic only: no real case data.

use std::sync::Arc;

use forensic_rs::prelude::testing::{InMemoryVirtualFileSystem, TestingRegistry};
use forensic_rs::prelude::*;
use frnsc_ntfs::fixtures::indx::{index_entry, indx_record};
use frnsc_ntfs::fixtures::sds::{sds_entry, security_descriptor};
use frnsc_ntfs::fixtures::usn::usn_v2;
use frnsc_ntfs::fixtures::volume::{VolumeBuilder, ROOT};
use frnsc_ntfs::fixtures::{
    file_name_value_times, times, MftBuilder, RecordBuilder, DAY, FILE_TIME_2020 as T,
};
use frnsc_ntfs::secure::SDS_BLOCK;
use frnsc_ntfs::FileRef;
use frnsc_vsys::fixtures::{gpt_disk, GptPart, BASIC_DATA};

use crate::catalog::Catalog;
use crate::evidence;

/// One named input.
pub struct Corpus {
    pub name: String,
    /// `garbage` corpora must not panic; every other check needs records to compare.
    pub kind: CorpusKind,
    pub sources: TriageSources,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusKind {
    /// No filesystem, no registry.
    Empty,
    /// Hostile bytes where parsers look for their artifacts.
    Garbage,
    /// Well-formed synthetic evidence.
    Valid,
    /// Evidence supplied on the command line.
    External,
}

/// Where artifacts live, relative to the system drive. Parsers disagree on whether a path
/// starts with `C:` (Amcache and the hive reader do, browser history does not), so garbage is
/// planted under both spellings.
const ARTIFACT_PATHS: &[&str] = &[
    "$MFT",
    "$Extend/$UsnJrnl:$J",
    "$Extend/$J",
    "$Secure:$SDS",
    "$I30",
    "Windows/AppCompat/Programs/Amcache.hve",
    "Windows/System32/Config/SYSTEM",
    "Windows/System32/Config/SOFTWARE",
    "Users/alice/NTUSER.DAT",
    "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
    "Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History",
    "Windows/Prefetch/CMD.EXE-12345678.pf",
    "Windows/System32/winevt/Logs/Security.evtx",
    "Windows/System32/sru/SRUDB.dat",
];

/// File signatures, so a parser gets past its magic check and into the body.
const MAGICS: &[&[u8]] = &[
    b"FILE0",
    b"regf",
    b"SQLite format 3\0",
    b"ElfFile\0",
    b"MAM\x04",
    b"SCCA",
    b"INDX",
];

/// Bytes to plant at the n-th artifact path.
type Filler = Box<dyn Fn(usize) -> Vec<u8>>;

pub const FEATURE_USAGE_SID: &str = "S-1-5-21-1000-1000-1000-1001";

/// Every built-in corpus.
pub fn standard(catalog: &Catalog) -> Vec<Corpus> {
    let mut out = vec![Corpus {
        name: "empty".into(),
        kind: CorpusKind::Empty,
        sources: TriageSources::builder().build(),
    }];
    let noise = noise(64 * 1024);
    let garbage: [(&str, Filler); 4] = [
        ("garbage-zeros", Box::new(|n| vec![0u8; n])),
        ("garbage-ones", Box::new(|n| vec![0xFFu8; n])),
        (
            "garbage-noise",
            Box::new(move |n| noise[..n.min(noise.len())].to_vec()),
        ),
        ("garbage-truncated", Box::new(|_| Vec::new())),
    ];
    for (name, bytes) in garbage {
        out.push(garbage_corpus(name, |i| bytes(4096 + i * 512)));
    }
    let noise = noise_seeded(64 * 1024, 0xF0E1_D2C3);
    out.push(garbage_corpus("garbage-magic", |i| {
        let mut b = MAGICS[i % MAGICS.len()].to_vec();
        b.extend_from_slice(&noise[..8192]);
        b
    }));
    out.push(Corpus {
        name: "valid-loose-ntfs".into(),
        kind: CorpusKind::Valid,
        sources: TriageSources::builder()
            .vfs(Arc::new(loose_ntfs()))
            .registry(Arc::new(feature_usage_registry()))
            .acquisition(Acquisition::RemoteCollection)
            .build(),
    });
    out.extend(disk_corpus(catalog));
    out
}

fn garbage_corpus(name: &str, bytes: impl Fn(usize) -> Vec<u8>) -> Corpus {
    let mut fs = InMemoryVirtualFileSystem::new();
    for (i, p) in ARTIFACT_PATHS.iter().enumerate() {
        fs = fs
            .with_file(*p, bytes(i))
            .with_file(format!("C:/{p}"), bytes(i));
    }
    Corpus {
        name: name.into(),
        kind: CorpusKind::Garbage,
        sources: TriageSources::builder()
            .vfs(Arc::new(fs))
            .registry(Arc::new(garbage_registry()))
            .acquisition(Acquisition::ImageRead)
            .build(),
    }
}

/// FeatureUsage values of the wrong type and with hostile names.
fn garbage_registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    let base = format!(
        r"HKU\{FEATURE_USAGE_SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage"
    );
    reg.add_value(
        &format!(r"{base}\AppSwitched"),
        "\u{0}\u{FFFD}",
        RegValue::new_sz("not a counter"),
    );
    reg.add_value(
        &format!(r"{base}\AppLaunch"),
        "",
        RegValue::Binary(vec![0xFF; 3]),
    );
    reg.add_value(
        &format!(r"{base}\ShowJumpView"),
        &"A".repeat(4096),
        RegValue::from_u32(u32::MAX),
    );
    reg
}

/// A small, well-formed FeatureUsage key for one user.
pub fn feature_usage_registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    let base = format!(
        r"HKU\{FEATURE_USAGE_SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage"
    );
    reg.add_value(
        &format!(r"{base}\AppSwitched"),
        "Microsoft.Windows.Explorer",
        RegValue::from_u32(5),
    );
    reg.add_value(
        &format!(r"{base}\AppLaunch"),
        "Microsoft.Windows.Explorer",
        RegValue::from_u32(2),
    );
    reg.add_value(
        &format!(r"{base}\TrayButtonClicked"),
        "Clock",
        RegValue::from_u32(11),
    );
    reg
}

/// Loose NTFS metadata files, as a triage tool exports them: `$MFT`, `$J`, a `$I30` and `$SDS`.
pub fn loose_ntfs() -> InMemoryVirtualFileSystem {
    InMemoryVirtualFileSystem::new()
        .with_file("C/$MFT", loose_mft())
        .with_file("C/$Extend/$UsnJrnl%3A$J", usn_journal())
        .with_file("C/Temp/$I30", i30())
        .with_file("C/$Secure%3A$SDS", sds())
}

const TEMP: FileRef = FileRef::new(40, 1);

/// A loose `$MFT`: a directory, an allocated file, deleted files and one unreadable record.
pub fn loose_mft() -> Vec<u8> {
    let mut b = MftBuilder::new();
    b.put(
        40,
        RecordBuilder::file(40, 1)
            .directory()
            .std_info(T)
            .file_name(5, 5, "Temp", T)
            .build(),
    );
    b.put(
        41,
        RecordBuilder::file(41, 1)
            .std_info(T)
            .file_name(40, 1, "report.pdf", T)
            .resident_data("", b"%PDF")
            .build(),
    );
    b.put(
        42,
        RecordBuilder::file(42, 2)
            .deleted()
            .std_info(T + DAY)
            .file_name(40, 1, "mimi.exe", T)
            .resident_data("", b"MZ")
            .build(),
    );
    b.put(43, vec![0x5A; 1024]);
    b.build()
}

/// Two journal entries for a script in `Temp`, preceded by a sparse (zeroed) region.
fn usn_journal() -> Vec<u8> {
    let mut j = vec![0u8; 8192];
    j.extend(usn_v2(FileRef::new(60, 1), TEMP, 0x2000, T, 0x100, "x.ps1"));
    j.extend(usn_v2(
        FileRef::new(60, 1),
        TEMP,
        0x2050,
        T + 10,
        0x8000_0200,
        "x.ps1",
    ));
    j
}

/// One index node of `Temp`: a live entry, and a deleted one left in slack.
fn i30() -> Vec<u8> {
    let key = |name: &str| file_name_value_times(TEMP, name, &times(T), 1, 4096, 10);
    let live = vec![
        index_entry(FileRef::new(41, 1), &key("report.pdf")),
        index_entry(FileRef::new(44, 1), &key("notes.txt")),
    ];
    let slack = index_entry(FileRef::new(42, 1), &key("mimi.exe"));
    indx_record(0, &live, &slack, 4096)
}

/// Two security descriptors, mirrored in the second block as NTFS does.
fn sds() -> Vec<u8> {
    let mut stream = vec![0u8; 2 * SDS_BLOCK as usize];
    let e1 = sds_entry(256, 0, &security_descriptor("S-1-5-21-1000-1000-1000-1001"));
    let e2 = sds_entry(257, 0x90, &security_descriptor("S-1-5-18"));
    stream[..e1.len()].copy_from_slice(&e1);
    stream[0x90..0x90 + e2.len()].copy_from_slice(&e2);
    let (a, b) = stream.split_at_mut(SDS_BLOCK as usize);
    b[..0x90 + e2.len()].copy_from_slice(&a[..0x90 + e2.len()]);
    stream
}

/// A GPT disk with one NTFS partition, opened through the same code path as a real image.
fn disk_corpus(catalog: &Catalog) -> Vec<Corpus> {
    let base: Arc<dyn FileSystem> =
        Arc::new(InMemoryVirtualFileSystem::new().with_file("disk.raw", disk_image()));
    let ev = evidence::open_image_on(&base, "disk.raw", catalog, Acquisition::ImageRead);
    ev.sources
        .into_iter()
        .map(|s| {
            let mut b = TriageSources::builder()
                .vfs(s.vfs)
                .acquisition(s.acquisition)
                .registry(Arc::new(feature_usage_registry()));
            if let Some(r) = s.registry {
                b = b.registry(r);
            }
            Corpus {
                name: format!("valid-{}", s.label),
                kind: CorpusKind::Valid,
                sources: b.build(),
            }
        })
        .collect()
}

/// `disk.raw`: GPT, one partition, NTFS holding a small Windows-like tree and a deleted tool.
pub fn disk_image() -> Vec<u8> {
    let mut b = VolumeBuilder::new(false);
    let windows = b.dir(ROOT, "Windows");
    let system32 = b.dir(windows, "System32");
    b.file(system32, "notepad.exe", b"MZ notepad");
    let users = b.dir(ROOT, "Users");
    let alice = b.dir(users, "alice");
    let tool = b.file(alice, "mimi.exe", b"MZ tool");
    b.delete(tool);
    let ntfs = b.build();

    const FIRST_LBA: u64 = 2048;
    let sectors = ntfs.len() as u64 / 512;
    let mut disk = gpt_disk(
        512,
        FIRST_LBA + sectors + 64,
        &[GptPart {
            type_guid: BASIC_DATA,
            first_lba: FIRST_LBA,
            last_lba: FIRST_LBA + sectors - 1,
            name: "Windows",
        }],
    );
    let at = (FIRST_LBA * 512) as usize;
    disk[at..at + ntfs.len()].copy_from_slice(&ntfs);
    disk
}

fn noise(n: usize) -> Vec<u8> {
    noise_seeded(n, 0x9E37_79B9_7F4A_7C15)
}

/// Deterministic pseudo-random bytes (xorshift64), so every benchmark run sees the same input.
fn noise_seeded(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
