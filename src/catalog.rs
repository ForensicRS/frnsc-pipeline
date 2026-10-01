//! Every ForensicRS crate this pipeline knows about, and what it contributes.
//!
//! This is the one list to edit when a crate gains a parser factory. A crate either:
//!
//! * contributes an [`ArtifactParserFactory`] (the pipeline runs it and the readiness benchmark
//!   checks it),
//! * contributes a [`FormatFactory`] (the evidence layer uses it to mount images, volumes and
//!   embedded files),
//! * is a backend used to build a source (a `Registry`, an `EventLogReader`), or
//! * is a **gap**: it parses an artifact but has no parser factory, so a pipeline cannot use it.
//!   Gaps are reported, never papered over with an adapter here: the factory belongs in the
//!   crate itself.

use std::sync::Arc;

use forensic_rs::prelude::*;

/// What one catalog entry contributes.
pub enum Component {
    Parser(Arc<dyn ArtifactParserFactory>),
    Format(Arc<dyn FormatFactory>),
    /// A trait backend the evidence layer builds sources from. Not run as a parser.
    Backend {
        provides: &'static str,
        note: &'static str,
    },
    /// Parses an artifact, but cannot run in a pipeline yet.
    Gap {
        artifact: &'static str,
        reason: &'static str,
    },
}

pub struct CatalogEntry {
    pub crate_name: &'static str,
    pub component: Component,
}

impl CatalogEntry {
    fn parser(crate_name: &'static str, factory: impl ArtifactParserFactory + 'static) -> Self {
        Self {
            crate_name,
            component: Component::Parser(Arc::new(factory)),
        }
    }
    fn format(crate_name: &'static str, factory: impl FormatFactory + 'static) -> Self {
        Self {
            crate_name,
            component: Component::Format(Arc::new(factory)),
        }
    }

    /// Short label for the component kind.
    pub fn kind(&self) -> &'static str {
        match self.component {
            Component::Parser(_) => "parser",
            Component::Format(_) => "format",
            Component::Backend { .. } => "backend",
            Component::Gap { .. } => "gap",
        }
    }

    /// Parser id, format name, backend trait or gap artifact.
    pub fn name(&self) -> String {
        match &self.component {
            Component::Parser(p) => p.descriptor().id.to_string(),
            Component::Format(f) => f.name().to_string(),
            Component::Backend { provides, .. } => (*provides).to_string(),
            Component::Gap { artifact, .. } => (*artifact).to_string(),
        }
    }

    /// Human description of the entry.
    pub fn detail(&self) -> String {
        match &self.component {
            Component::Parser(p) => p.descriptor().description.to_string(),
            Component::Format(f) => format!("yields {:?}", f.yields()),
            Component::Backend { note, .. } => (*note).to_string(),
            Component::Gap { reason, .. } => (*reason).to_string(),
        }
    }
}

/// The set of crates the pipeline is built from.
pub struct Catalog {
    entries: Vec<CatalogEntry>,
}

impl Catalog {
    /// Every crate in the ForensicRS workspace that builds on this platform.
    pub fn standard() -> Self {
        use frnsc_ntfs::parser::{
            I30ParserFactory, MftParserFactory, SdsParserFactory, UsnParserFactory,
        };
        let entries = vec![
            // Parsers.
            CatalogEntry::parser("forensic-rs", ContainerInventoryParser::new()),
            CatalogEntry::parser("forensic-rs", RegistryCollector::new()),
            CatalogEntry::parser("frnsc-ntfs", MftParserFactory::default()),
            CatalogEntry::parser("frnsc-ntfs", I30ParserFactory::default()),
            CatalogEntry::parser("frnsc-ntfs", UsnParserFactory::default()),
            CatalogEntry::parser("frnsc-ntfs", SdsParserFactory::default()),
            CatalogEntry::parser("frnsc-amcache", frnsc_amcache::parser::AmCacheParserFactory::new()),
            CatalogEntry::parser(
                "frnsc-winreg-activity",
                frnsc_winreg_activity::feature_usage::FeatureUsageParserFactory::new(),
            ),
            CatalogEntry::parser("frnsc-winreg-activity", frnsc_winreg_activity::BamParserFactory::new()),
            CatalogEntry::parser("frnsc-winreg-activity", frnsc_winreg_activity::RunKeysParserFactory::new()),
            CatalogEntry::parser("frnsc-winreg-activity", frnsc_winreg_activity::ServicesParserFactory::new()),
            CatalogEntry::parser("frnsc-winreg-activity", frnsc_winreg_activity::ShimCacheParserFactory::new()),
            CatalogEntry::parser(
                "frnsc-winreg-activity",
                frnsc_winreg_activity::MountedDevicesParserFactory::new(),
            ),
            CatalogEntry::parser(
                "frnsc-winreg-activity",
                frnsc_winreg_activity::WordWheelQueryParserFactory::new(),
            ),
            CatalogEntry::parser("frnsc-sqlite", frnsc_sqlite::artifacts::parser::BrowserHistoryParserFactory::new()),
            CatalogEntry::parser("frnsc-prefetch", frnsc_prefetch::parser::PrefetchParserFactory::new()),
            CatalogEntry::parser("frnsc-winevt", frnsc_winevt::EvtxParserFactory::new()),
            CatalogEntry::parser("frnsc-esedb", frnsc_esedb::srum::SrumParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::unix::utmp::UtmpParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::log::syslog::SyslogParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::log::audit::AuditParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::shell::ShellHistoryParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::packages::PackagesParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::unix::accounts::AccountsParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::unix::ssh::SshParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::schedule::ScheduleParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::units::UnitsParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::identity::IdentityParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::journal::JournalParserFactory::new()),
            CatalogEntry::parser("frnsc-linux", frnsc_linux::containers::ContainersParserFactory::new()),
            // Formats that yield a FileSystem: these are what images, partitions and embedded
            // containers are opened with.
            CatalogEntry::format("forensic-rs", SplitRawFactory::new()),
            CatalogEntry::format("frnsc-vsys", frnsc_vsys::VolumeSystemFactory::new()),
            CatalogEntry::format("frnsc-ntfs", frnsc_ntfs::volume::NtfsFormatFactory),
            CatalogEntry::format("frnsc-ole", frnsc_ole::OleFileSystemFactory::new()),
            // Formats that yield a registry, database or event log.
            CatalogEntry::format("frnsc-hive", frnsc_hive::factory::HiveFormatFactory::new()),
            CatalogEntry::format("frnsc-sqlite", frnsc_sqlite::sqlite::factory::SqliteFormatFactory),
            CatalogEntry::format("frnsc-esedb", frnsc_esedb::EseFormatFactory),
            CatalogEntry::format("frnsc-winevt", frnsc_winevt::EvtxFormatFactory),
            // Backends.
            CatalogEntry {
                crate_name: "frnsc-hive",
                component: Component::Backend {
                    provides: "Registry",
                    note: "HiveRegistryReader: HKLM hives and per-user NTUSER.DAT, with LOG1/LOG2 replay; \
                           becomes ctx.registry() for every volume that has the hives",
                },
            },
            // Gaps.
            CatalogEntry {
                crate_name: "frnsc-triage",
                component: Component::Gap {
                    artifact: "Collection",
                    reason: "Windows-only live collector (acquisition, not parsing), still on the 0.13 \
                             RegistryReader API",
                },
            },
            CatalogEntry {
                crate_name: "frnsc-liveregistry-rs",
                component: Component::Gap {
                    artifact: "LiveRegistry",
                    reason: "Windows-only live Registry backend; not usable on images or on this platform",
                },
            },
        ];
        Self { entries }
    }

    /// Builds a catalog from explicit entries (tests and custom pipelines).
    pub fn from_entries(entries: Vec<CatalogEntry>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// `(crate, factory)` for every parser, in catalog order.
    pub fn parsers(&self) -> impl Iterator<Item = (&'static str, &Arc<dyn ArtifactParserFactory>)> {
        self.entries.iter().filter_map(|e| match &e.component {
            Component::Parser(p) => Some((e.crate_name, p)),
            _ => None,
        })
    }

    /// Every format factory, optionally only those that yield `kind`.
    pub fn formats(&self, kind: Option<MountKind>) -> Vec<Arc<dyn FormatFactory>> {
        self.entries
            .iter()
            .filter_map(|e| match &e.component {
                Component::Format(f) if kind.is_none_or(|k| f.yields() == k) => Some(Arc::clone(f)),
                _ => None,
            })
            .collect()
    }

    /// A registry holding every parser. Fails on a duplicate parser id.
    pub fn parser_registry(&self) -> ForensicResult<ParserRegistry> {
        let mut registry = ParserRegistry::new();
        for (_, p) in self.parsers() {
            registry.register(Arc::clone(p))?;
        }
        Ok(registry)
    }

    /// A resolver over the format factories that yield `kind` (all of them when `None`).
    pub fn resolver(&self, kind: Option<MountKind>) -> MountResolver {
        MountResolver::builder()
            .factories(self.formats(kind))
            .build()
    }

    /// Resolver for a single named format (e.g. `"ntfs"`).
    pub fn resolver_for(&self, names: &[&str]) -> MountResolver {
        let factories = self
            .formats(None)
            .into_iter()
            .filter(|f| names.contains(&f.name()));
        MountResolver::builder().factories(factories).build()
    }
}
