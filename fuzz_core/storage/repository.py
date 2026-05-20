from __future__ import annotations
import json, sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS vuldocs(
  doc_id TEXT PRIMARY KEY, protocol TEXT, filename TEXT, raw_path TEXT, sha256 TEXT,
  size INTEGER, source TEXT, created_at TEXT, json TEXT
);
CREATE TABLE IF NOT EXISTS kb_entries(
  entry_id TEXT PRIMARY KEY, protocol TEXT, doc_id TEXT, coarse_type TEXT, vuln_type TEXT,
  cwe TEXT, title TEXT, created_at TEXT, json TEXT
);
CREATE TABLE IF NOT EXISTS seed_generations(
  generation_id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, generation_mode TEXT, created_at TEXT, json TEXT
);
CREATE TABLE IF NOT EXISTS debug_sessions(
  session_id TEXT PRIMARY KEY, protocol TEXT, coarse_type TEXT, status TEXT, created_at TEXT, json TEXT
);
CREATE TABLE IF NOT EXISTS vuln_history(
  record_id TEXT PRIMARY KEY, protocol TEXT, coarse_type TEXT, vuln_type TEXT, cwe TEXT, created_at TEXT, json TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuldocs_protocol ON vuldocs(protocol);
CREATE INDEX IF NOT EXISTS idx_kb_protocol_type ON kb_entries(protocol, coarse_type, vuln_type, cwe);
CREATE INDEX IF NOT EXISTS idx_debug_protocol_type ON debug_sessions(protocol, coarse_type);
CREATE INDEX IF NOT EXISTS idx_history_protocol_type ON vuln_history(protocol, coarse_type);
"""

class Repository:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)

    def connect(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def upsert_vuldoc(self, rec: dict[str, Any]):
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO vuldocs VALUES(?,?,?,?,?,?,?,?,?)",
                (rec["doc_id"], rec["protocol"], rec["filename"], rec["raw_path"], rec["sha256"], rec["size"], rec.get("source","upload"), rec["created_at"], json.dumps(rec, ensure_ascii=False)),
            )

    def list_vuldocs(self, protocol: str, limit: int=100, offset: int=0):
        with self.connect() as db:
            rows=db.execute("SELECT json FROM vuldocs WHERE protocol=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (protocol, limit, offset)).fetchall()
        return [json.loads(r["json"]) for r in rows]

    def get_vuldoc(self, doc_id: str):
        with self.connect() as db:
            row=db.execute("SELECT json FROM vuldocs WHERE doc_id=?", (doc_id,)).fetchone()
        return json.loads(row["json"]) if row else None

    def upsert_kb_entry(self, rec: dict[str, Any]):
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO kb_entries VALUES(?,?,?,?,?,?,?,?,?)",
                (rec["entry_id"], rec["protocol"], rec.get("doc_id"), rec.get("coarse_type","unknown"), rec.get("vuln_type","unknown"), rec.get("cwe",""), rec.get("title",""), rec["created_at"], json.dumps(rec, ensure_ascii=False)),
            )

    def list_kb(self, protocol: str, coarse_type: str|None=None, vuln_type: str|None=None, cwe: str|None=None, keyword: str|None=None, limit: int=100, offset: int=0):
        q="SELECT json FROM kb_entries WHERE protocol=?"
        args=[protocol]
        if coarse_type:
            q+=" AND coarse_type=?"; args.append(coarse_type)
        if vuln_type:
            q+=" AND vuln_type=?"; args.append(vuln_type)
        if cwe:
            q+=" AND cwe=?"; args.append(cwe)
        q+=" ORDER BY created_at DESC LIMIT ? OFFSET ?"; args += [limit, offset]
        with self.connect() as db:
            rows=db.execute(q, args).fetchall()
        items=[json.loads(r["json"]) for r in rows]
        if keyword:
            k=keyword.lower()
            items=[x for x in items if k in json.dumps(x, ensure_ascii=False).lower()]
        return items

    def get_kb(self, entry_id: str):
        with self.connect() as db:
            row=db.execute("SELECT json FROM kb_entries WHERE entry_id=?", (entry_id,)).fetchone()
        return json.loads(row["json"]) if row else None

    def save_seed_generation(self, rec: dict[str, Any]):
        with self.connect() as db:
            db.execute("INSERT INTO seed_generations(protocol,generation_mode,created_at,json) VALUES(?,?,?,?)",
                       (rec["protocol"], rec["generation_mode"], rec["created_at"], json.dumps(rec, ensure_ascii=False)))

    def save_debug_session(self, rec: dict[str, Any]):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO debug_sessions VALUES(?,?,?,?,?,?)",
                       (rec["session_id"], rec["protocol"], rec.get("classification",{}).get("coarse_type","unknown"), rec.get("status","unknown"), rec["created_at"], json.dumps(rec, ensure_ascii=False)))

    def list_debug_sessions(self, protocol: str, coarse_type: str|None=None, limit: int=100, offset: int=0):
        q="SELECT json FROM debug_sessions WHERE protocol=?"; args=[protocol]
        if coarse_type: q+=" AND coarse_type=?"; args.append(coarse_type)
        q+=" ORDER BY created_at DESC LIMIT ? OFFSET ?"; args += [limit, offset]
        with self.connect() as db:
            rows=db.execute(q,args).fetchall()
        return [json.loads(r["json"]) for r in rows]

    def get_debug_session(self, session_id: str):
        with self.connect() as db:
            row=db.execute("SELECT json FROM debug_sessions WHERE session_id=?", (session_id,)).fetchone()
        return json.loads(row["json"]) if row else None

    def upsert_history(self, rec: dict[str, Any]):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO vuln_history VALUES(?,?,?,?,?,?,?)",
                       (rec["record_id"], rec["protocol"], rec.get("coarse_type","unknown"), rec.get("vuln_type","unknown"), rec.get("cwe",""), rec["created_at"], json.dumps(rec, ensure_ascii=False)))

    def list_history(self, protocol: str, coarse_type: str|None=None, limit: int=100, offset: int=0):
        q="SELECT json FROM vuln_history WHERE protocol=?"; args=[protocol]
        if coarse_type: q+=" AND coarse_type=?"; args.append(coarse_type)
        q+=" ORDER BY created_at DESC LIMIT ? OFFSET ?"; args += [limit, offset]
        with self.connect() as db:
            rows=db.execute(q,args).fetchall()
        return [json.loads(r["json"]) for r in rows]

    def get_history(self, record_id: str):
        with self.connect() as db:
            row=db.execute("SELECT json FROM vuln_history WHERE record_id=?", (record_id,)).fetchone()
        return json.loads(row["json"]) if row else None

    def protocols(self):
        with self.connect() as db:
            rows=db.execute("""
              SELECT protocol FROM vuldocs UNION SELECT protocol FROM kb_entries
              UNION SELECT protocol FROM seed_generations UNION SELECT protocol FROM debug_sessions
              UNION SELECT protocol FROM vuln_history
            """).fetchall()
        return sorted([r[0] for r in rows])

    def counts_by(self, table: str, protocol: str, field: str):
        allowed = {"kb_entries": {"coarse_type","vuln_type","cwe"}, "vuln_history": {"coarse_type","vuln_type","cwe"}}
        if table not in allowed or field not in allowed[table]:
            raise ValueError("invalid count request")
        with self.connect() as db:
            rows=db.execute(f"SELECT {field} AS k, COUNT(*) AS c FROM {table} WHERE protocol=? GROUP BY {field}", (protocol,)).fetchall()
        return {str(r["k"] or "unknown"): int(r["c"]) for r in rows}
