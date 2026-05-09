# fuzz-core-client-ts

Official TypeScript local client for the merged Python core.

It talks to the core through Unix Domain Socket JSON-RPC, so React+Ink TUI can use local IPC without importing Python modules.

## Usage

```ts
import { FuzzCoreClient } from "fuzz-core-client-ts";

const client = new FuzzCoreClient({ socketPath: "/tmp/fuzz-core.sock" });

const config = await client.config.get();
await client.config.patch({ afl: { afl_binary: "/usr/local/bin/afl-fuzz" } });

const protocol = await client.protocol.analyze({
  source_path: "/path/to/src",
  output_path: "/tmp/protocol.json",
  copy_to_scan_dir: true
});

const seeds = await client.seeds.generate({
  spec_path: "/tmp/protocol.json",
  output_dir: "/tmp/seeds",
  count: 8
});

const risk = await client.risk.analyze({
  source_path: "/path/to/src",
  output_path: "/tmp/final_analysis.json"
});

const instrument = await client.instrument.run({
  source_path: "/path/to/src",
  analysis_path: "/tmp/final_analysis.json",
  output_path: "/tmp/instrumented-copy"
});

const job = await client.jobs.create({
  afl: {
    afl_binary: "afl-fuzz",
    target_binary: "/path/to/target",
    input_dir: "/tmp/seeds",
    output_dir: "/tmp/out",
    run_cwd: "/path/to/build"
  }
});
```

## Notes

- Instrumentation defaults to in-place overwrite when `source_path` is a directory and `output_path` is omitted.
- When both a source root and an `output_path` are provided, the full source tree is copied first, then matching files are instrumented in the copy.
- Seed output directories are marked as generated directories so later source scans can skip them.
