# Protocol-scoped storage

Target layout:

```text
workspace/
  protocols/
    {protocol_slug}/
      specs/
      vuldocs/raw/
      vuldocs/distilled/
      vuldocs/chunks/
      kb/
      seeds/text/
      seeds/bin/
      risk/analyses/
      risk/previews/
      risk/instrumented/
      debug/sessions/
      debug/poc/
      debug/reports/
      history/vulns/
```

All writes go through `PathResolver`. Services must not concatenate workspace paths directly.

## Legacy default

If a legacy route receives no `protocol`, data goes to `legacy-default`.

## Migration

Dry run:

```bash
python scripts/migrate_workspace.py --legacy-root /path/to/old/backend --workspace ./workspace --protocol legacy-default
```

Apply:

```bash
python scripts/migrate_workspace.py --legacy-root /path/to/old/backend --workspace ./workspace --protocol modbustcp --apply
```

Conflict policy: existing destination files are preserved; migrated duplicates receive a timestamp suffix and sidecar metadata.
