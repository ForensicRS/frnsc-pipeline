# frnsc-pipeline

A complete forensic pipeline built from every ForensicRS crate, and a benchmark that tells
whether each parser is fit to run inside one.

Part of the [ForensicRS](https://github.com/ForensicRS) ecosystem, built on
[`forensic-rs`](https://github.com/ForensicRS/forensic-rs).

## What it does

```text
input (folder | raw / split-raw image)
  │  evidence.rs: MountResolver + ContainerFs
  │   image ─► split segments ─► partitions (frnsc-vsys) ─► NTFS volumes (frnsc-ntfs)
  ▼
one source per volume: FileSystem + Registry (frnsc-hive, from the hives on that volume)
  │  run.rs: TriagePipeline (or ParallelPipeline) per source
  ▼
parsers (catalog.rs) ─► analyzers (ExecutionCorrelator) ─► sinks
  ▼
<out>/summary.json
<out>/<NN-source>/timeline.jsonl   records + provenance id + confidence
<out>/<NN-source>/provenance.json  provenance side table
<out>/<NN-source>/findings.jsonl   analyzer findings, anomaly tallies, parser and hive errors
```

- **Every volume is its own source.** Records of two volumes are never merged.
- **The serial run is deterministic.** The same input produces byte-identical output.
- **`ExecutionCorrelator` joins Amcache with `$MFT`.** It reports executables that are
  deleted from, or absent in, the volume, and it follows hard links through `ntfs.paths`.

## Usage

```sh
cargo run --release -p frnsc-pipeline -- catalog
cargo run --release -p frnsc-pipeline -- run --input path/to/C --out out/ --host HOSTNAME
cargo run --release -p frnsc-pipeline -- run --input disk.raw --out out/ --host HOSTNAME --parallel
cargo run --release -p frnsc-pipeline -- bench --out readiness.md --json readiness.json
cargo run --release -p frnsc-pipeline -- bench --evidence path/to/C --evidence vol.ntfs --strict
```

`--host` is required because the host name is analyst input and the tool never guesses it.
`--acquisition` defaults to `image-read` for an image and `remote-collection` for a folder.

## Pipeline-readiness benchmark

`bench` runs every parser of the catalog alone, over these corpora:

- `empty`: no filesystem and no registry.
- Five `garbage-*` corpora (zeros, 0xFF, noise, empty files, real magic followed by noise).
  Each one plants its bytes at every well-known artifact path, under both `C:/…` and `…`.
- Two valid synthetic corpora (`fixtures.rs`):
  - loose NTFS files (`$MFT`, `$J`, `$I30`, `$SDS`) plus a FeatureUsage registry,
  - a GPT disk with an NTFS partition, opened through the same code path as a real image.
- Anything passed with `--evidence`.

| check | passes when |
|---|---|
| `descriptor` | the id is non-empty and unique, a version is set, and artifacts are declared |
| `empty` | with no sources, the parser neither panics nor emits a record |
| `garbage` | hostile bytes never make it panic |
| `coverage` | a valid corpus gives it records (`skip` means untested) |
| `determinism` | two runs give identical records and findings |
| `cancellation` | once the pipeline says stop, it emits nothing more |
| `provenance` | every record's provenance resolves, the host is the run's host, and `@timestamp` is a date |
| `parallel` | the parallel pipeline yields the same records as the serial one |

Crates that parse an artifact but have no `ArtifactParserFactory` are listed as **gaps**.
They are not wrapped here: the factory belongs in the crate itself.

## Adding a crate

1. Add the dependency to `Cargo.toml`.
2. Add a `CatalogEntry` in `src/catalog.rs`: a `Parser`, a `Format`, a `Backend`, or a
   `Gap` until it has a factory.
3. If no existing corpus feeds the parser, add a valid fixture in `src/fixtures.rs`, and plant
   its artifact path in `ARTIFACT_PATHS`.
4. Run `cargo test -p frnsc-pipeline` and `bench`. Once the parser passes, pin it in
   `tests/readiness.rs`.

## Development

```sh
cargo test -p frnsc-pipeline
../forensic-testenv/tools/fetch.py --crate frnsc-pipeline   # real samples for tests/real_samples.rs
```

## Coverage and limitations

- **Images:** raw, split raw (`.001`…), MBR/GPT and NTFS only. E01 and VHD(X) have no format
  factory yet, and neither do filesystems other than NTFS.
- **Folder layout:** folders must be rooted at the system drive (KAPE-style `C/`). The hive
  reader and Amcache look for fixed paths such as `Windows/System32/Config`. On other layouts,
  for example Brimor Labs' flattened `registry/<user>_NTUSER.DAT`, those parsers skip, while
  the NTFS parsers still find their files by name.
- **Symbolic links** inside a collection are not followed by walk-based discovery.
- **Parallel mode:** records are written in completion order, and provenance ids follow that
  order. Record content is the same as in serial mode.
- **Gaps:** Prefetch, SRUM and event logs are not in the timeline until their crates expose
  parser factories. `summary.json` lists them for each run.
