//! Analyzers that need more than one parser's output: what a pipeline adds over running each
//! parser alone.

use std::collections::BTreeMap;

use forensic_rs::dictionary;
use forensic_rs::prelude::*;
use frnsc_ntfs::fields as ntfs;

const AMCACHE_RECORD_TYPE: &str = "amcache.record_type";
const AMCACHE_FILE: &str = "InventoryApplicationFile";
const AMCACHE_FILE_PATH: &str = "amcache.application_file.path";

/// Joins Amcache's record of executed/installed files with the volume's `$MFT`.
///
/// A file Amcache knows about, on this volume, that the `$MFT` holds only as a deleted entry
/// (or not at all) is worth a look: tools are often deleted after use.
///
/// Reports in `finalize`, which both pipelines call once, after every parser. When the run had no
/// Amcache or no `$MFT` at all it stays silent: with one side missing, every Amcache path would be
/// "absent from the `$MFT`". Paths on other drives than `C:` are counted but never reported: this
/// volume cannot answer for them.
#[derive(Default)]
pub struct ExecutionCorrelator {
    /// Normalized path -> raw Amcache path, for files on the system drive.
    executed: BTreeMap<String, String>,
    /// Normalized path -> (raw MFT path, any in-use entry has it).
    on_volume: BTreeMap<String, (String, bool)>,
    other_drive: u64,
    mft_seen: bool,
    amcache_seen: bool,
}

impl ExecutionCorrelator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Analyzer for ExecutionCorrelator {
    fn name(&self) -> &str {
        "execution_correlator"
    }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![
            RegistryArtifacts::AmCache.into(),
            Artifact::Windows(WindowsArtifacts::MFT),
        ]
    }

    fn analyze(
        &mut self,
        data: &ForensicData,
        _ctx: &TriageContext,
        _out: &mut Vec<Finding>,
    ) -> ForensicResult<()> {
        if data.field_as_str(AMCACHE_RECORD_TYPE) == Some(AMCACHE_FILE) {
            self.amcache_seen = true;
            if let Some(raw) = data.field_as_str(AMCACHE_FILE_PATH) {
                match system_drive_path(raw) {
                    Some(norm) => {
                        self.executed.entry(norm).or_insert_with(|| raw.to_string());
                    }
                    None => self.other_drive += 1,
                }
            }
        } else if data.field_as_str(ntfs::RECORD_TYPE) == Some(ntfs::RECORD_TYPE_MFT_ENTRY) {
            self.mft_seen = true;
            let in_use = data.field_as_u64(ntfs::IN_USE) == Some(1);
            // `file.path` is one name of the entry; a hard-linked file (every System32 binary,
            // linked from WinSxS) has the others in `ntfs.paths`.
            let mut paths: Vec<&str> = match data.field(ntfs::PATHS) {
                Some(Field::Array(all)) => all.iter().map(|p| p.as_ref()).collect(),
                _ => Vec::new(),
            };
            paths.extend(data.field_as_str(dictionary::FILE_PATH));
            for raw in paths {
                let slot = self
                    .on_volume
                    .entry(volume_path(raw))
                    .or_insert_with(|| (raw.to_string(), false));
                slot.1 |= in_use;
            }
        }
        Ok(())
    }

    fn finalize(&mut self, _ctx: &TriageContext, out: &mut Vec<Finding>) -> ForensicResult<()> {
        if !(self.mft_seen && self.amcache_seen) {
            return Ok(());
        }
        for (norm, amcache_raw) in &self.executed {
            let (title, description, mft_raw) = match self.on_volume.get(norm) {
                Some((_, true)) => continue,
                Some((mft_raw, false)) => (
                    "File known to Amcache survives only as a deleted $MFT entry",
                    "Amcache recorded this file, and the $MFT holds it only as a deleted entry.",
                    Some(mft_raw.as_str()),
                ),
                None => (
                    "File known to Amcache is absent from the $MFT",
                    "Amcache recorded this file, but no $MFT entry, allocated or deleted, has its path.",
                    None,
                ),
            };
            let mut f = Finding::new(
                FindingSeverity::Medium,
                FindingCategory::SuspiciousActivity,
                title,
            )
            .with_description(format!("{description} Path: {amcache_raw}"))
            .with_artifact(RegistryArtifacts::AmCache.into())
            .with_metadata(
                Text::Borrowed("amcache.path"),
                Text::Owned(amcache_raw.clone()),
            );
            if let Some(raw) = mft_raw {
                f = f.with_metadata(Text::Borrowed("mft.path"), Text::Owned(raw.to_string()));
            }
            out.push(f);
        }
        Ok(())
    }
}

/// `c:\Windows\x.exe` -> `\windows\x.exe`; `None` for another drive or a relative path.
fn system_drive_path(raw: &str) -> Option<String> {
    let lower = raw.replace('/', "\\").to_lowercase();
    lower
        .strip_prefix("c:")
        .filter(|r| r.starts_with('\\'))
        .map(str::to_string)
}

/// `\Windows\x.exe` (or `Windows/x.exe`) -> `\windows\x.exe`.
fn volume_path(raw: &str) -> String {
    let lower = raw.replace('/', "\\").to_lowercase();
    if lower.starts_with('\\') {
        lower
    } else {
        format!("\\{lower}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_rs::prelude::testing::test_provenance_id;

    fn amcache(path: &str) -> ForensicData {
        let mut d = ForensicData::new("H", RegistryArtifacts::AmCache.into(), test_provenance_id());
        d.set(AMCACHE_RECORD_TYPE, AMCACHE_FILE);
        d.set(AMCACHE_FILE_PATH, path.to_string());
        d
    }

    fn mft(path: &str, links: &[&str], in_use: bool) -> ForensicData {
        let mut d = ForensicData::new(
            "H",
            Artifact::Windows(WindowsArtifacts::MFT),
            test_provenance_id(),
        );
        d.set(ntfs::RECORD_TYPE, ntfs::RECORD_TYPE_MFT_ENTRY);
        d.set(dictionary::FILE_PATH, path.to_string());
        d.set(ntfs::IN_USE, in_use);
        d.add_field(
            ntfs::PATHS,
            Field::Array(links.iter().map(|l| Text::Owned(l.to_string())).collect()),
        );
        d
    }

    fn correlate(records: &[ForensicData]) -> Vec<Finding> {
        let ctx = TriageContext::new("H", "t");
        let mut a = ExecutionCorrelator::new();
        let mut out = Vec::new();
        for r in records {
            a.analyze(r, &ctx, &mut out).unwrap();
        }
        a.finalize(&ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn reports_deleted_and_absent_files_once() {
        let out = correlate(&[
            amcache(r"C:\Users\alice\mimi.exe"),
            amcache(r"c:\tools\gone.exe"),
            amcache(r"c:\windows\system32\csrss.exe"),
            amcache(r"D:\portable\x.exe"),
            mft(r"\Users\alice\mimi.exe", &[r"\Users\alice\mimi.exe"], false),
            // Hard link: the System32 name is only in `ntfs.paths`.
            mft(
                r"\Windows\WinSxS\x\csrss.exe",
                &[
                    r"\Windows\System32\csrss.exe",
                    r"\Windows\WinSxS\x\csrss.exe",
                ],
                true,
            ),
        ]);
        let titles: Vec<(&str, &str)> = out
            .iter()
            .map(|f| {
                (
                    f.title.as_str(),
                    f.metadata.get("amcache.path").map_or("", |p| p.as_ref()),
                )
            })
            .collect();
        assert_eq!(
            titles,
            vec![
                (
                    "File known to Amcache is absent from the $MFT",
                    r"c:\tools\gone.exe"
                ),
                (
                    "File known to Amcache survives only as a deleted $MFT entry",
                    r"C:\Users\alice\mimi.exe"
                ),
            ]
        );
    }

    #[test]
    fn silent_when_one_side_is_missing() {
        assert!(correlate(&[amcache(r"c:\tools\gone.exe")]).is_empty());
        assert!(correlate(&[mft(r"\x.exe", &[], false)]).is_empty());
    }

    #[test]
    fn normalizes_paths_across_artifacts() {
        assert_eq!(
            system_drive_path(r"C:\Windows\Evil.exe").as_deref(),
            Some(r"\windows\evil.exe")
        );
        assert_eq!(system_drive_path(r"d:\tools\x.exe"), None);
        assert_eq!(system_drive_path("x.exe"), None);
        assert_eq!(volume_path(r"\Windows\Evil.exe"), r"\windows\evil.exe");
        assert_eq!(volume_path("Windows/Evil.exe"), r"\windows\evil.exe");
    }
}
