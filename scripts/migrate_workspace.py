#!/usr/bin/env python3
from __future__ import annotations
import argparse, shutil, json
from pathlib import Path
from datetime import datetime, timezone

def safe_proto(p): return (p or "legacy-default").strip().lower().replace("/", "-") or "legacy-default"

def main():
    ap=argparse.ArgumentParser(description="Migrate legacy shared fuzz-core/backend files into protocol-scoped workspace")
    ap.add_argument("--legacy-root", required=True)
    ap.add_argument("--workspace", default="./workspace")
    ap.add_argument("--protocol", default="legacy-default")
    ap.add_argument("--apply", action="store_true")
    args=ap.parse_args()
    legacy=Path(args.legacy_root).resolve()
    root=Path(args.workspace).resolve()/"protocols"/safe_proto(args.protocol)
    plan=[]
    mappings=[
      ("uploads/Vuldoc", "vuldocs/raw"),
      ("uploads/Riskresult", "risk/analyses"),
      ("extract/output/best", "specs"),
      ("corpus/queue", "seeds/bin"),
    ]
    for src_rel,dst_rel in mappings:
        src=legacy/src_rel
        if src.exists():
            for p in src.rglob("*"):
                if p.is_file():
                    dst=root/dst_rel/p.name
                    plan.append({"src":str(p),"dst":str(dst)})
                    if args.apply:
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        if dst.exists():
                            dst=dst.with_name(dst.stem+"-migrated-"+datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")+dst.suffix)
                        shutil.copy2(p,dst)
                        meta={"protocol":safe_proto(args.protocol),"source":"legacy_migration","src":str(p),"migrated_at":datetime.now(timezone.utc).isoformat()}
                        dst.with_suffix(dst.suffix+".metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"apply":args.apply,"items":plan}, ensure_ascii=False, indent=2))
if __name__ == "__main__":
    main()
