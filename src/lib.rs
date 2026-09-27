//! A complete ForensicRS pipeline, and a benchmark of how well each parser fits in one.
//!
//! * [`catalog`]: every crate of the ecosystem and what it contributes (parser, format,
//!   backend), plus the crates that cannot run in a pipeline yet.
//! * [`evidence`]: a collection folder or a disk image becomes one source per volume.
//! * [`run`]: every parser over every source, with the cross-artifact [`analyzers`], written
//!   to a timeline, a provenance side table and a findings file.
//! * [`readiness`]: the same parsers against empty, hostile and valid inputs ([`fixtures`]),
//!   reported as a pass/fail matrix.

pub mod analyzers;
pub mod catalog;
pub mod collect;
pub mod evidence;
pub mod fixtures;
pub mod readiness;
pub mod run;
