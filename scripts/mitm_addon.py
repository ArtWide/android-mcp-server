"""mitmdump addon: append one JSON line per HTTP(S) flow to a file.

Loaded by NetworkCaptureManager via `mitmdump -s scripts/mitm_addon.py`. The
output path is taken from the MITM_FLOWFILE environment variable. Runs inside
mitmdump's interpreter (which provides the `mitmproxy` package), so the project
venv does not need mitmproxy installed.

Each line carries both a compact summary (method/url/status/sizes, used by
network_list_flows) and the full request/response detail (headers + decoded,
size-capped bodies, used by network_get_flow to render packet views for the
analysis report).
"""

import base64
import json
import os

_FILE = os.environ.get("MITM_FLOWFILE", "flows.jsonl")

# Cap stored bodies so the JSONL stays small; the summary keeps the true length.
_BODY_CAP = int(os.environ.get("MITM_BODY_CAP", "16384"))


def _headers(msg):
    """Headers as an ordered list of [name, value], preserving duplicates."""
    try:
        return [[k, v] for k, v in msg.headers.items(multi=True)]
    except Exception:
        return []


def _body(msg):
    """Decoded body as text when possible, else base64, with a size cap.

    Returns a dict: {text|b64 (one is null), len (true byte length), truncated}.
    `msg.content` is the decompressed body; `get_text` decodes it per charset.
    """
    try:
        raw = msg.content
    except Exception:
        raw = getattr(msg, "raw_content", None)
    if not raw:
        return {"text": None, "b64": None, "len": 0, "truncated": False}

    length = len(raw)
    try:
        text = msg.get_text(strict=False)
    except Exception:
        text = None

    if text is not None:
        return {
            "text": text[:_BODY_CAP],
            "b64": None,
            "len": length,
            "truncated": len(text) > _BODY_CAP,
        }
    return {
        "text": None,
        "b64": base64.b64encode(raw[:_BODY_CAP]).decode("ascii"),
        "len": length,
        "truncated": length > _BODY_CAP,
    }


def response(flow):
    try:
        req = flow.request
        resp = flow.response
        entry = {
            # --- summary (network_list_flows) ---
            "ts": req.timestamp_start,
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "url": req.pretty_url,
            "http_version": getattr(req, "http_version", ""),
            "status": resp.status_code if resp else None,
            "reason": resp.reason if resp else "",
            "req_len": len(req.raw_content or b""),
            "resp_len": len(resp.raw_content or b"") if resp else 0,
            "content_type": resp.headers.get("content-type", "") if resp else "",
            # --- detail (network_get_flow / packet render) ---
            "req_headers": _headers(req),
            "req_body": _body(req),
            "resp_headers": _headers(resp) if resp else [],
            "resp_body": _body(resp) if resp else {"text": None, "b64": None,
                                                    "len": 0, "truncated": False},
        }
        with open(_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
