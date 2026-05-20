from __future__ import annotations
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository

class KBService:
    def __init__(self, paths: PathResolver, repo: Repository):
        self.paths, self.repo = paths, repo

    def search(self, protocol: str, coarse_type: str|None=None, vuln_type: str|None=None, cwe: str|None=None, keyword: str|None=None, limit: int=50, offset: int=0):
        return self.repo.list_kb(self.paths.protocol(protocol), coarse_type, vuln_type, cwe, keyword, limit, offset)

    def get(self, vuln_id: str):
        return self.repo.get_kb(vuln_id)

    def summary(self, protocol: str):
        proto=self.paths.protocol(protocol)
        items=self.repo.list_kb(proto, limit=10000)
        return {
            "protocol": proto,
            "total": len(items),
            "by_coarse_type": self.repo.counts_by("kb_entries", proto, "coarse_type"),
            "by_vuln_type": self.repo.counts_by("kb_entries", proto, "vuln_type"),
            "by_cwe": self.repo.counts_by("kb_entries", proto, "cwe"),
            "top_entries": items[:10],
        }

    def graph(self, protocol: str):
        proto=self.paths.protocol(protocol)
        items=self.repo.list_kb(proto, limit=10000)
        nodes=[{"id": f"protocol:{proto}", "label": proto, "type": "protocol"}]
        edges=[]
        seen=set()
        for it in items:
            eid=f"vuln:{it['entry_id']}"
            nodes.append({"id": eid, "label": it.get("title") or it["entry_id"], "type":"vuln", "coarse_type": it.get("coarse_type")})
            edges.append({"source": f"protocol:{proto}", "target": eid, "type":"has_vuln"})
            for typ in [it.get("coarse_type","unknown"), it.get("cwe","")]:
                if not typ: continue
                nid=f"type:{typ}"
                if nid not in seen:
                    nodes.append({"id":nid, "label":typ, "type":"category"}); seen.add(nid)
                edges.append({"source": eid, "target": nid, "type":"classified_as"})
            if it.get("doc_id"):
                did=f"doc:{it['doc_id']}"
                if did not in seen:
                    nodes.append({"id": did, "label": it.get("source_ref") or it["doc_id"], "type":"document"}); seen.add(did)
                edges.append({"source": eid, "target": did, "type":"derived_from"})
        return {"protocol": proto, "nodes": nodes, "edges": edges}

    def timeline(self, protocol: str):
        proto=self.paths.protocol(protocol)
        docs=self.repo.list_vuldocs(proto, limit=10000)
        kb=self.repo.list_kb(proto, limit=10000)
        events=[]
        for d in docs:
            events.append({"time": d["created_at"], "kind":"vuldoc_uploaded", "id":d["doc_id"], "title":d["filename"]})
        for e in kb:
            events.append({"time": e["created_at"], "kind":"kb_distilled", "id":e["entry_id"], "title":e.get("title"), "coarse_type":e.get("coarse_type")})
        return {"protocol": proto, "events": sorted(events, key=lambda x:x["time"])}

    def retrieval_context(self, protocol: str, keyword: str|None=None, limit: int=8):
        hits=self.search(protocol, keyword=keyword, limit=limit)
        return [{"entry_id":h["entry_id"], "title":h.get("title"), "summary":h.get("summary"), "coarse_type":h.get("coarse_type"), "evidence":h.get("evidence",[])[:3]} for h in hits]
