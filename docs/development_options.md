# Development controls

The public binary accepts only essential acquisition inputs. Build controls
separately so the normal executable cannot silently acquire a different scope:

```sh
cargo build --release --locked --offline --features development-options --target-dir target-dev
cargo test --locked --offline --features development-options --target-dir target-dev
sudo ./target-dev/release/kernel_dump capture --scope full-ram --output full_control
```

Development-only flags are `--scope full-ram|kernel-focused`, `--chunk-mib 1..16`
and `--queue-depth 1..16`. The default remains kernel-focused with user/cache exclusions.
These are validation controls, not additional public operating modes. Full-RAM
controls need space for the machine's RAM plus metadata. Unsafe/unmapped pages
still cause incomplete status; the name is not a promise of byte availability.

Full captures preserve contemporaneous flag RLE and relative exclusions for a
same-byte derivation. Derive alternatives from that image and those flags;
do not combine old bytes with current live PFN flags. Check image/ledger hashes
and successful analyzer exit codes before comparing normalized result rows.
Separate analyzer timeouts, invalid addresses, missing rows and acquisition errors.

The Python prototype under `reference/python` is historical research tooling.
Its policy differs from the final Rust tool. It is not called by the executable.
The dated experiment archive retains exact derivation, analyzer and fault scripts.

## Writer unwind injection — 2026-10-15 source candidate

Only a build with `development-options` reads
`KERNEL_DUMP_TEST_WRITER_PANIC`. Its accepted values are `before-receive` (after
the real reader is spawned) and `after-header` (after the first selected LiME
header is written, before its payload). Other nonempty values fail setup. The
public build does not read this environment variable and has no injection flag.

```sh
sudo env KERNEL_DUMP_TEST_WRITER_PANIC=before-receive \
  ./target-dev/release/kernel_dump capture --output panic_before_receive
sudo env KERNEL_DUMP_TEST_WRITER_PANIC=after-header \
  ./target-dev/release/kernel_dump capture --output panic_after_header
```

Use new outputs in a dedicated test directory with an existing parent. In a
writable environment with progressing source I/O, each command should exit2,
record `errors[].stage = writer_panic`, finish reader join, and publish a failed
manifest with `memory.lime.partial`; it must not publish `memory.lime`. The
normal Rust panic hook still writes diagnostics to stderr before recovery.
The manifest records the development injection point and reader join timestamps.
The `before-receive` point alone does not prove the producer filled the queue.

Then run one normal acquisition into a different new output with the variable
unset and verify it. Synthetic tests should exercise the actual `acquire`
function, including a producer blocked at handoff, rather than only testing an
isolated channel. Set injection in a dedicated child process; do not mutate a
process-wide environment while unrelated Rust tests run in parallel.

These commands are a regression handoff, not tests already run. The boundary
catches Rust unwinding panics only. Abort, SIGKILL, double panic, recovery-path
failure and indefinitely blocked I/O remain outside its guarantee.


## Verifier input bounds

Both builds enforce a16MiB manifest-byte cap before JSON deserialization and a128KiB JSONL-record cap; per-record payload length is limited to16MiB. Scope must be kernel-focused/full-ram and status complete_for_policy/partial/failed. These caps do not authenticate metadata or bound total RSS. Full-RAM scope is development-only, not a public fallback or strict kernel-only mode.
