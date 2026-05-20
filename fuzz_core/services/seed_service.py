from __future__ import annotations
import json, uuid
from pathlib import Path
from ..models import SeedGenerationResult
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository
from .kb_service import KBService

class SeedService:
    def __init__(self, paths: PathResolver, repo: Repository, kb: KBService):
        self.paths, self.repo, self.kb = paths, repo, kb

    def _latest_spec(self, proto: str):
        specs=sorted(self.paths.subdir(proto, "specs").glob("*"), key=lambda p:p.stat().st_mtime if p.exists() else 0, reverse=True)
        return specs[0] if specs else None

    def save_spec(self, protocol: str|None, content: str, name: str="protocol_spec.json"):
        proto=self.paths.protocol(protocol)
        sid=f"spec-{uuid.uuid4().hex[:10]}-{self.paths.safe_filename(name)}"
        p=self.paths.file(proto, "specs", sid)
        p.write_text(content, encoding="utf-8")
        meta={"protocol": proto, "spec_id": sid, "path": str(p)}
        p.with_suffix(p.suffix+".metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta

    def generate(self, protocol: str|None, spec_path: str|None=None, keyword: str|None=None, count: int=8, output_dir: str|None=None, allow_fallback: bool=True):
        proto=self.paths.protocol(protocol)
        spec=Path(spec_path) if spec_path else self._latest_spec(proto)
        spec_exists=bool(spec and spec.exists())
        kb_hits=self.kb.retrieval_context(proto, keyword, limit=8)
        docs=self.repo.list_vuldocs(proto, limit=20)
        warnings=[]
        if spec_exists and kb_hits:
            mode="spec_plus_kb"; conf=0.82
        elif spec_exists:
            mode="spec_only"; conf=0.68
        elif kb_hits:
            mode="kb_only_fallback"; conf=0.58; warnings.append("No protocol spec was found; generated from protocol-scoped KB entries.")
        elif docs and allow_fallback:
            mode="raw_doc_fallback"; conf=0.42; warnings.append("No spec or distilled KB found; generated from raw protocol-scoped documents.")
        else:
            mode="degraded_no_spec"; conf=0.22; warnings.append("No spec, KB, or VulDoc context found; generated generic seed templates.")
        out=Path(output_dir) if output_dir else self.paths.subdir(proto, "seeds/bin")
        out.mkdir(parents=True, exist_ok=True)
        seeds=[]
        base_names=["length-edge","empty","single-field","max-count","type-confusion","state-reset","fragmented","random-small"]
        context=json.dumps(kb_hits[:2], ensure_ascii=False)[:120]
        for i in range(max(1, count)):
            name=f"seed_{i:03d}_{base_names[i%len(base_names)]}.bin"
            payload=(f"FUZZCORE|{proto}|{mode}|{i}|{keyword or ''}|{context}\n").encode()
            path=out/name
            path.write_bytes(payload)
            seeds.append({"name":name, "path":str(path), "size":len(payload), "explanation":f"Generated using {mode}"})
        result=SeedGenerationResult(
            protocol=proto, generation_mode=mode, seeds=seeds,
            used_spec_id=str(spec) if spec_exists else None,
            used_vuldoc_ids=[d["doc_id"] for d in docs[:8]] if mode in {"raw_doc_fallback","kb_only_fallback","spec_plus_kb"} else [],
            used_kb_entry_ids=[h["entry_id"] for h in kb_hits],
            confidence=conf, warnings=warnings, output_dir=str(out),
        ).model_dump()
        self.repo.save_seed_generation(result)
        (out/"generation_metadata.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return result
