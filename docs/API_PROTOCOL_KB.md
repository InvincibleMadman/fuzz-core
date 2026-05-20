# Added protocol-aware APIs

All responses use the modern wrapper:

```json
{"ok": true, "message": "ok", "data": {}}
```

## Protocol discovery

- `GET /api/v1/protocols`
- `GET /api/v1/protocols/{protocol}/summary`

## VulDoc

- `POST /api/v1/protocols/{protocol}/vuldocs/upload`
  - multipart field: `files`
- `POST /api/v1/protocols/{protocol}/vuldocs/distill`
  - optional body: `{"doc_ids":["doc-..."]}`
- `GET /api/v1/protocols/{protocol}/vuldocs`
- `GET /api/v1/protocols/{protocol}/vuldocs/{doc_id}`

## Knowledge base

- `GET /api/v1/protocols/{protocol}/kb/summary`
- `GET /api/v1/protocols/{protocol}/kb/search?coarse_type=&vuln_type=&cwe=&keyword=`
- `GET /api/v1/protocols/{protocol}/kb/vulns`
- `GET /api/v1/protocols/{protocol}/kb/vulns/{vuln_id}`
- `GET /api/v1/protocols/{protocol}/kb/graph`
- `GET /api/v1/protocols/{protocol}/kb/timeline`

## Vulnerability history

- `GET /api/v1/protocols/{protocol}/vulns/history`
- `GET /api/v1/protocols/{protocol}/vulns/history?coarse_type=bounds-check`
- `GET /api/v1/protocols/{protocol}/vulns/history/{record_id}`

## Existing APIs

The existing modern and legacy API paths remain registered. Legacy routes keep `is_success/msg/data`.
