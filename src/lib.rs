//! A complete ForensicRS pipeline, and a benchmark of how well each parser fits in one.
//!
//! * [`catalog`]: every crate of the ecosystem and what it contributes (parser, format,
//!   backend), plus the crates that cannot run in a pipeline yet.
//! * [`evidence`]: a collection folder or a disk image becomes one source per volume, with the
//!   `frnsc-artifacts` catalog attached so parsers resolve the definitions they declare.
//! * [`kb`]: what the pipeline can do with each ForensicArtifacts definition.
//! * [`run`]: every parser over every source, with the cross-artifact [`analyzers`], written
//!   to a timeline, a provenance side table and a findings file.
//! * [`readiness`]: the same parsers against empty, hostile and valid inputs ([`fixtures`]),
//!   reported as a pass/fail matrix.
//! * [`skip`]: why a parser did not run — recomputes the reason `can_parse`'s bare `bool`
//!   collapses, shared by [`run`] and [`readiness`].

pub mod analyzers;
pub mod catalog;
pub mod collect;
pub mod evidence;
pub mod fixtures;
pub mod kb;
pub mod readiness;
pub mod run;
pub mod skip;
