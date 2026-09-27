//! Turns what the analyst points at into pipeline sources.
//!
//! * A **collection folder** (a triage export rooted at the system drive, e.g. KAPE's `C/`)
//!   is one source: the host filesystem under that folder, with embedded containers (split
//!   raw images, OLE files, disk images) opened transparently by [`ContainerFs`].
//! * A **disk image** is opened explicitly, hop by hop: split segments, then the partition
//!   table, then each NTFS volume. Every volume is its own source, so records and findings of
//!   two volumes are never merged. Partitions no factory can mount are reported, not dropped.
//!
//! Each source gets a `Registry` built from the hives it holds, when it holds any.

use std::path::Path;
use std::sync::Arc;

use forensic_rs::prelude::*;
use frnsc_hive::reader::HiveRegistryReader;

use crate::catalog::Catalog;

/// How many container hops an image may take before a volume (split -> media -> partition).
const MAX_DEPTH: usize = 4;

/// One volume or folder the pipeline runs over.
pub struct EvidenceSource {
    /// Stable, human-readable name: the folder path, or `image/p1` for a partition.
    pub label: String,
    pub locator: EvidenceLocator,
    pub vfs: Arc<dyn FileSystem>,
    pub registry: Option<Arc<dyn Registry>>,
    pub acquisition: Acquisition,
    /// Integrity findings raised while opening the source (e.g. hive log replay).
    pub findings: Vec<Finding>,
}

impl EvidenceSource {
    pub fn sources(&self, resolver: &Arc<MountResolver>) -> TriageSources {
        let mut b = TriageSources::builder()
            .vfs(Arc::clone(&self.vfs))
            .acquisition(self.acquisition)
            .mount_resolver(Arc::clone(resolver));
        if let Some(r) = &self.registry {
            b = b.registry(Arc::clone(r));
        }
        b.build()
    }
}

/// Something in the input that could not become a source.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Unmounted {
    pub label: String,
    pub reason: String,
}

/// Everything found in the input.
pub struct Evidence {
    pub sources: Vec<EvidenceSource>,
    pub unmounted: Vec<Unmounted>,
}

/// Opens a collection folder or a disk image, deciding by what `path` is.
pub fn open(
    path: &Path,
    catalog: &Catalog,
    acquisition: Option<Acquisition>,
) -> ForensicResult<Evidence> {
    if path.is_dir() {
        open_folder(
            path,
            catalog,
            acquisition.unwrap_or(Acquisition::RemoteCollection),
        )
    } else {
        open_image(path, catalog, acquisition.unwrap_or(Acquisition::ImageRead))
    }
}

/// A triage collection rooted at the system drive.
pub fn open_folder(
    path: &Path,
    catalog: &Catalog,
    acquisition: Acquisition,
) -> ForensicResult<Evidence> {
    let root = host_path(path)?;
    let base: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new(
        root.as_str(),
        Arc::new(StdVirtualFS::new()),
    ));
    let resolver = Arc::new(catalog.resolver(Some(MountKind::FileSystem)));
    let policy = DescentPolicy::from_resolver(&resolver);
    let vfs: Arc<dyn FileSystem> = Arc::new(ContainerFs::new(base, resolver).with_policy(policy));
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(root.as_str())));
    Ok(Evidence {
        sources: vec![source(folder_label(path), locator, vfs, acquisition)],
        unmounted: Vec::new(),
    })
}

/// A raw or split-raw disk image, or a bare volume image.
pub fn open_image(
    path: &Path,
    catalog: &Catalog,
    acquisition: Acquisition,
) -> ForensicResult<Evidence> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ForensicError::other("evidence", "image name is not valid UTF-8".into()))?;
    let base: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new(
        host_path(parent)?.as_str(),
        Arc::new(StdVirtualFS::new()),
    ));
    Ok(open_image_on(&base, name, catalog, acquisition))
}

/// Like [`open_image`], for an image file `name` inside any filesystem (e.g. an in-memory one).
pub fn open_image_on(
    base: &Arc<dyn FileSystem>,
    name: &str,
    catalog: &Catalog,
    acquisition: Acquisition,
) -> Evidence {
    let finder = VolumeFinder {
        volumes: catalog.resolver_for(&["ntfs"]),
        media: catalog.resolver_for(&["split-raw", "vsys"]),
        acquisition,
    };
    let mut evidence = Evidence {
        sources: Vec::new(),
        unmounted: Vec::new(),
    };
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(name)));
    finder.descend(base, FPath::new(name), name, locator, 0, &mut evidence);
    if evidence.sources.is_empty() && evidence.unmounted.is_empty() {
        evidence.unmounted.push(Unmounted {
            label: name.to_string(),
            reason: "no volume found".into(),
        });
    }
    evidence
}

struct VolumeFinder {
    /// Factories that turn a byte range into a volume filesystem.
    volumes: MountResolver,
    /// Factories that split a byte range into smaller ones (segments, partitions).
    media: MountResolver,
    acquisition: Acquisition,
}

impl VolumeFinder {
    fn descend(
        &self,
        fs: &Arc<dyn FileSystem>,
        path: &FPath,
        label: &str,
        locator: EvidenceLocator,
        depth: usize,
        out: &mut Evidence,
    ) {
        let unmounted = |reason: String| Unmounted {
            label: label.to_string(),
            reason,
        };
        let not_volume = match self.try_mount(&self.volumes, fs, path, &locator) {
            Ok(vfs) => {
                out.sources
                    .push(source(label.to_string(), locator, vfs, self.acquisition));
                return;
            }
            Err(e) => e,
        };
        if depth >= MAX_DEPTH {
            out.unmounted.push(unmounted(format!(
                "no volume within {MAX_DEPTH} container hops ({not_volume})"
            )));
            return;
        }
        let media = match self.try_mount(&self.media, fs, path, &locator) {
            Ok(media) => media,
            Err(not_media) => {
                out.unmounted.push(unmounted(format!(
                    "not a volume ({not_volume}), nor a partition table or split image ({not_media})"
                )));
                return;
            }
        };
        let children = match media.read_dir(FPath::new("")) {
            Ok(it) => it,
            Err(e) => {
                out.unmounted
                    .push(unmounted(format!("cannot list partitions: {e}")));
                return;
            }
        };
        let mut entries = Vec::new();
        for child in children {
            match child {
                Ok(c) if c.file_type == VFileType::File => entries.push(c.path),
                Ok(_) => {}
                Err(e) => out
                    .unmounted
                    .push(unmounted(format!("partition entry unreadable: {e}"))),
            }
        }
        entries.sort();
        for child in entries {
            let child_label = format!("{label}/{}", child.as_str());
            let child_locator = locator.clone().push(LocatorSegment::Path(child.clone()));
            self.descend(
                &media,
                child.as_path(),
                &child_label,
                child_locator,
                depth + 1,
                out,
            );
        }
    }

    fn try_mount(
        &self,
        resolver: &MountResolver,
        fs: &Arc<dyn FileSystem>,
        path: &FPath,
        locator: &EvidenceLocator,
    ) -> Result<Arc<dyn FileSystem>, String> {
        let file = fs.open(path).map_err(|e| format!("cannot open: {e}"))?;
        let mounted = resolver
            .resolve(
                fs,
                locator,
                file,
                Some(MountKind::FileSystem),
                &CancellationToken::new(),
            )
            .map_err(|e| e.to_string())?;
        mounted
            .as_file_system()
            .cloned()
            .ok_or_else(|| "mounted as something other than a filesystem".to_string())
    }
}

fn source(
    label: String,
    locator: EvidenceLocator,
    vfs: Arc<dyn FileSystem>,
    acquisition: Acquisition,
) -> EvidenceSource {
    let (registry, findings) = registry_from(&vfs);
    EvidenceSource {
        label,
        locator,
        vfs,
        registry,
        acquisition,
        findings,
    }
}

/// Builds a `Registry` from the machine hives and the users' `NTUSER.DAT` on `fs`, with the
/// reader's integrity findings. `None` when the source holds no machine hive. A source not laid
/// out like a Windows volume (a triage collection) is searched by hive name
/// ([`HiveRegistryReader::load_from_fs`]).
pub fn registry_from(fs: &Arc<dyn FileSystem>) -> (Option<Arc<dyn Registry>>, Vec<Finding>) {
    let (reader, findings) = HiveRegistryReader::load_from_fs(fs);
    (reader.map(|r| Arc::new(r) as Arc<dyn Registry>), findings)
}

/// The last two components of a folder (`kape/C`): short, and still tells two collections apart.
/// The full path stays in the source's locator.
fn folder_label(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    let tail = &parts[parts.len().saturating_sub(2)..];
    if tail.is_empty() {
        path.display().to_string()
    } else {
        tail.join("/")
    }
}

fn host_path(path: &Path) -> ForensicResult<String> {
    let abs = std::fs::canonicalize(path)?;
    abs.to_str()
        .map(str::to_string)
        .ok_or_else(|| ForensicError::other("evidence", "evidence path is not valid UTF-8".into()))
}
