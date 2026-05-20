from __future__ import annotations
import json, uuid, shutil
from pathlib import Path
from ..storage.path_resolver import PathResolver

SOURCE_SUFFIXES={".c",".cc",".cpp",".h",".hpp",".py",".go",".rs"}

class RiskService:
    def __init__(self, paths: PathResolver):
        self.paths=paths

    def analyze(self, protocol: str|None, source_path: str):
        proto=self.paths.protocol(protocol)
        src=Path(source_path)
        findings=[]
        if src.exists():
            files=[src] if src.is_file() else [p for p in src.rglob("*") if p.suffix.lower() in SOURCE_SUFFIXES and ".fuzz_core_generated" not in p.parts]
            for p in files[:200]:
                text=p.read_text(encoding="utf-8", errors="ignore")
                risk=0
                if any(k in text for k in ["strcpy","memcpy","sprintf","gets"]): risk+=7
                if any(k in text.lower() for k in ["decode","parse","packet","frame"]): risk+=2
                if risk:
                    findings.append({"file":str(p), "risk_score":min(10,risk), "reason":"parser or unsafe memory primitive"})
        out=self.paths.file(proto, "risk/analyses", f"risk-{uuid.uuid4().hex[:10]}.json")
        rec={"protocol":proto,"source_path":source_path,"findings":findings,"result_path":str(out)}
        out.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        return rec

    def preview(self, protocol: str|None):
        proto=self.paths.protocol(protocol)
        files=sorted(self.paths.subdir(proto, "risk/analyses").glob("*.json"), key=lambda p:p.stat().st_mtime, reverse=True)
        return json.loads(files[0].read_text(encoding="utf-8")) if files else {"protocol":proto,"findings":[]}

    def upload_result(self, protocol: str|None, content: bytes, filename: str):
        proto=self.paths.protocol(protocol)
        out=self.paths.file(proto, "risk/analyses", f"upload-{uuid.uuid4().hex[:10]}-{self.paths.safe_filename(filename)}")
        out.write_bytes(content)
        return {"protocol":proto, "path":str(out), "filename":filename}

    def instrument(self, protocol: str|None, input_path: str, output_path: str|None=None):
        proto=self.paths.protocol(protocol)
        src=Path(input_path)
        if not src.exists():
            raise FileNotFoundError(input_path)
        if output_path:
            dst=Path(output_path)
            if src.is_dir():
                if dst.exists(): shutil.rmtree(dst)
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".fuzz_core_generated"))
            else:
                dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src,dst)
        else:
            dst=src
        changed=[]
        files=[dst] if dst.is_file() else [p for p in dst.rglob("*") if p.suffix.lower() in SOURCE_SUFFIXES and ".fuzz_core_generated" not in p.parts]
        for p in files:
            text=p.read_text(encoding="utf-8", errors="ignore")
            if "__POLAR_INS" in text: continue
            marker="\n/* fuzz-core risk marker: __POLAR_INS((protocol_scope_marker)) */\n"
            p.write_text(text+marker, encoding="utf-8")
            changed.append(str(p))
        meta={"protocol":proto, "input_path":input_path, "output_path":str(dst), "changed_files":changed}
        out=self.paths.file(proto, "risk/instrumented", f"instrument-{uuid.uuid4().hex[:10]}.json")
        out.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta
