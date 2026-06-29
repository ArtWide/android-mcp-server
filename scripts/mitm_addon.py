"""mitmdump addon: append one JSON line per HTTP(S) flow to a file.

Loaded by NetworkCaptureManager via `mitmdump -s scripts/mitm_addon.py`. The
output path is taken from the MITM_FLOWFILE environment variable. Runs inside
mitmdump's interpreter (which provides the `mitmproxy` package), so the project
venv does not need mitmproxy installed.
"""

import json
import os

_FILE = os.environ.get("MITM_FLOWFILE", "flows.jsonl")


def response(flow):
    try:
        req = flow.request
        resp = flow.response
        entry = {
            "ts": req.timestamp_start,
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "url": req.pretty_url,
            "status": resp.status_code if resp else None,
            "req_len": len(req.raw_content or b""),
            "resp_len": len(resp.raw_content or b"") if resp else 0,
            "content_type": resp.headers.get("content-type", "") if resp else "",
        }
        with open(_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
