"""Render source code to an annotated PNG for the analysis report.

Turns a decompiled code snippet (e.g. from jadx_read_source) into an image that
looks like a code viewer: syntax-highlighted lines, a line-number gutter, red
boxes around the problematic lines, and Korean inline comments explaining *why*
the code is malicious.

The renderer only draws; deciding which lines matter and writing the Korean
"why" text is the analyst's / model's job (passed in via `annotations` and
`highlight_lines`). This keeps the house style deterministic while the analytic
content stays flexible.
"""

import os
from pathlib import Path

from PIL import Image as PILImage
from PIL import ImageDraw, ImageFont
from pygments import lex
from pygments.lexers import get_lexer_by_name
from pygments.token import Comment, Keyword, Name, Number, Operator, String
from pygments.util import ClassNotFound

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"

# Light theme roughly matching the sample report's JADX capture.
_BG = (250, 250, 250)
_GUTTER_BG = (238, 238, 238)
_GUTTER_FG = (150, 150, 150)
_DEFAULT_FG = (32, 32, 32)
_GREEN = (0, 128, 0)        # comments + Korean annotations
_RED = (214, 40, 40)        # highlight boxes
_KEYWORD = (0, 0, 200)
_STRING = (163, 21, 21)
_NUMBER = (9, 134, 88)
_NAME = (121, 94, 38)

# Dark theme for log / packet "evidence" figures (dynamic-execution evidence:
# logcat, process list, /proc/net, etc.) with a right-side annotation column.
_D_BG = (30, 32, 38)
_D_GUTTER_BG = (24, 26, 31)
_D_GUTTER_FG = (110, 116, 128)
_D_FG = (214, 218, 226)
_D_GREEN = (126, 197, 122)    # # comments + >> annotations
_D_RED = (224, 78, 78)        # boxes
_D_CONNECT = (96, 102, 116)   # box -> annotation connector

# Flow-diagram theme (class/function call flow; malicious path highlighted).
_F_BG = (24, 30, 41)
_F_PANEL = (44, 56, 74)
_F_INK = (223, 231, 242)
_F_MUTE = (139, 158, 186)
_F_TITLE = (159, 179, 214)
# kind -> (border, fill)
_F_KIND = {
    "mal": ((224, 86, 86), (58, 32, 36)),
    "aux": ((120, 137, 160), (34, 44, 60)),
    "normal": ((79, 140, 210), (28, 46, 74)),
}
_F_EDGE = {"mal": (224, 86, 86), "aux": (120, 137, 160), "normal": (120, 137, 160)}

_CODE_FONT_CANDIDATES = [
    os.environ.get("CODE_FONT_PATH", ""),
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "DejaVuSansMono.ttf",
]
_KR_FONT_CANDIDATES = [
    os.environ.get("KR_FONT_PATH", ""),
    "C:/Windows/Fonts/malgun.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
]


def _load_font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont:
    for path in candidates:
        if path and Path(path).is_file():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    # Last resort: a bitmap default (no scaling, no Korean glyphs). Better than
    # crashing; callers on a properly-fonted host never hit this.
    return ImageFont.load_default()


def _is_ascii(text: str) -> bool:
    return all(ord(c) < 128 for c in text)


def _color_for(ttype) -> tuple[int, int, int]:
    if ttype in Comment:
        return _GREEN
    if ttype in Keyword:
        return _KEYWORD
    if ttype in String:
        return _STRING
    if ttype in Number:
        return _NUMBER
    if ttype in Name.Function or ttype in Name.Class or ttype in Name.Decorator:
        return _NAME
    if ttype in Operator:
        return _DEFAULT_FG
    return _DEFAULT_FG


def _tokenize_lines(code: str, language: str) -> list[list[tuple]]:
    """Return lines, each a list of (color, text) segments."""
    try:
        lexer = get_lexer_by_name(language)
    except ClassNotFound:
        lexer = get_lexer_by_name("text")
    lines: list[list[tuple]] = [[]]
    for ttype, value in lex(code, lexer):
        color = _color_for(ttype)
        parts = value.split("\n")
        for i, part in enumerate(parts):
            if i > 0:
                lines.append([])
            part = part.replace("\t", "    ")
            if part:
                lines[-1].append((color, part))
    # A trailing newline yields a spurious empty final line; drop it.
    if len(lines) > 1 and not lines[-1]:
        lines.pop()
    return lines


def _merge_ranges(nums: list[int]) -> list[tuple[int, int]]:
    """Collapse a list of line numbers into (start, end) inclusive ranges."""
    if not nums:
        return []
    s = sorted(set(nums))
    ranges = [(s[0], s[0])]
    for n in s[1:]:
        if n == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], n)
        else:
            ranges.append((n, n))
    return ranges


class CodeImageRenderer:
    def __init__(self, output_dir: str | None = None, font_size: int = 18,
                 reports_dir: str | None = None) -> None:
        # Where the rendered PNGs land. `reports_dir` (from config/env) is used
        # verbatim when given, so the analyst can point it at a path the report
        # renderer (render_report.py, a separate sandbox) can also read; else
        # default to <workspace>/reports.
        if reports_dir:
            self.outdir = Path(reports_dir)
        else:
            self.outdir = (Path(output_dir) if output_dir else DEFAULT_WORKSPACE) / "reports"
        self.font_size = font_size

    def render_code_image(
        self,
        code: str,
        language: str = "java",
        highlight_lines: list[int] | None = None,
        annotations: list[dict] | None = None,
        title: str = "",
        start_line: int = 1,
    ) -> str:
        """Render `code` to a PNG and return the file path.

        Args:
            code: source text (a focused snippet, not a whole file).
            language: pygments lexer name (java, xml, text, ...).
            highlight_lines: 1-based line numbers to box in red (relative to the
                snippet; consecutive numbers merge into one box).
            annotations: [{"line": int, "text": "<한국어 설명>"}] drawn as green
                inline `// ...` comments at the end of that line.
            title: optional caption drawn above the code.
            start_line: the number shown for the first line in the gutter.
        """
        highlight_lines = highlight_lines or []
        ann_by_line: dict[int, str] = {}
        for a in annotations or []:
            try:
                ann_by_line[int(a["line"])] = str(a["text"])
            except (KeyError, ValueError, TypeError):
                continue

        code_font = _load_font(_CODE_FONT_CANDIDATES, self.font_size)
        kr_font = _load_font(_KR_FONT_CANDIDATES, self.font_size)
        title_font = _load_font(_KR_FONT_CANDIDATES, self.font_size + 4)

        lines = _tokenize_lines(code, language)

        # Drop highlights / annotations that point at a blank or out-of-range
        # line — those would draw an EMPTY box (or a floating comment) with no
        # code inside, the artifact seen in report figures. Keep only targets
        # (gutter-numbered) that have visible content.
        content_lines = {
            start_line + i for i, segs in enumerate(lines)
            if any(t.strip() for _, t in segs)
        }
        skipped_hl = sorted(set(highlight_lines) - content_lines)
        skipped_ann = sorted(k for k in ann_by_line if k not in content_lines)
        highlight_lines = [ln for ln in highlight_lines if ln in content_lines]
        ann_by_line = {k: v for k, v in ann_by_line.items() if k in content_lines}
        if skipped_hl or skipped_ann:
            import sys
            print(f"[render_code_image] skipped empty/out-of-range targets: "
                  f"highlights={skipped_hl} annotations={skipped_ann}",
                  file=sys.stderr)

        # Metrics. Baseline-align mixed fonts on a shared baseline per line.
        ascent = max(code_font.getmetrics()[0], kr_font.getmetrics()[0])
        descent = max(code_font.getmetrics()[1], kr_font.getmetrics()[1])
        line_pad = 6
        line_h = ascent + descent + line_pad
        pad = 16

        scratch = ImageDraw.Draw(PILImage.new("RGB", (1, 1)))
        char_w = scratch.textlength("M", font=code_font) or self.font_size * 0.6
        last_no = start_line + len(lines) - 1
        gutter_w = int(char_w * (len(str(last_no)) + 2))

        title_h = (line_h + pad) if title else 0

        # Measuring pass: widest drawn line (code + inline annotation).
        max_x = 0
        for idx, segs in enumerate(lines):
            x = pad + gutter_w
            for _, text in segs:
                seg_font = code_font if _is_ascii(text) else kr_font
                x += scratch.textlength(text, font=seg_font)
            ann = ann_by_line.get(start_line + idx)
            if ann:
                x += scratch.textlength("  // " + ann, font=kr_font)
            max_x = max(max_x, x)
        if title:
            max_x = max(max_x, pad + scratch.textlength(title, font=title_font))
        width = int(max_x + pad)
        height = int(pad + title_h + len(lines) * line_h + pad)

        img = PILImage.new("RGB", (width, height), _BG)
        draw = ImageDraw.Draw(img)

        # Gutter background.
        draw.rectangle([0, 0, pad + gutter_w - int(char_w / 2), height], fill=_GUTTER_BG)

        if title:
            draw.text((pad, pad), title, font=title_font, fill=_DEFAULT_FG)

        top0 = pad + title_h
        line_top = {}  # snippet line no -> y of the box top
        for idx, segs in enumerate(lines):
            lineno = start_line + idx
            baseline = top0 + idx * line_h + ascent
            line_top[lineno] = top0 + idx * line_h

            # Gutter line number (right-aligned in the gutter).
            num = str(lineno)
            nx = pad + gutter_w - int(char_w) - scratch.textlength(num, font=code_font)
            draw.text((nx, baseline), num, font=code_font, fill=_GUTTER_FG, anchor="ls")

            x = pad + gutter_w
            for color, text in segs:
                seg_font = code_font if _is_ascii(text) else kr_font
                draw.text((x, baseline), text, font=seg_font, fill=color, anchor="ls")
                x += scratch.textlength(text, font=seg_font)

            ann = ann_by_line.get(lineno)
            if ann:
                draw.text((x, baseline), "  // " + ann, font=kr_font,
                          fill=_GREEN, anchor="ls")

        # Red boxes for highlighted (merged) line ranges, drawn last (outline).
        for lo, hi in _merge_ranges(highlight_lines):
            if lo not in line_top or hi not in line_top:
                continue
            top = line_top[lo] - 1
            bottom = line_top[hi] + line_h - line_pad + 1
            draw.rectangle([pad + gutter_w - 2, top, width - int(pad / 2), bottom],
                           outline=_RED, width=2)

        self.outdir.mkdir(parents=True, exist_ok=True)
        # Deterministic-ish filename from content so repeated renders don't pile up.
        stem = f"code-{abs(hash((code, tuple(highlight_lines), title))) & 0xffffffff:08x}"
        path = self.outdir / f"{stem}.png"
        img.save(path, "PNG")
        return str(path)

    def render_log_evidence(
        self,
        text: str,
        annotations: list[dict] | None = None,
        highlight_lines: list[int] | None = None,
        title: str = "",
        start_line: int = 1,
    ) -> str:
        """Render log/packet evidence to a dark-theme PNG with a right-side
        annotation column (the report's dynamic-evidence figure style).

        Each annotated line gets a red box around the log line and a green
        `>> <설명>` in the right column, joined by a connector. Boxes default to
        the annotated lines. Annotations/highlights on a blank or out-of-range
        line are dropped (no empty boxes).

        Args:
            text: the raw log/packet text (logcat, process list, /proc/net, ...).
            annotations: [{"line": int, "text": "<한국어 설명>"}].
            highlight_lines: lines to box; default = the annotated lines.
            title: caption drawn above (e.g. "[증거5] 동적 실행 — C2 비콘").
            start_line: number shown for the first line in the gutter.
        """
        ann_by_line: dict[int, str] = {}
        for a in annotations or []:
            try:
                ann_by_line[int(a["line"])] = str(a["text"])
            except (KeyError, ValueError, TypeError):
                continue

        code_font = _load_font(_CODE_FONT_CANDIDATES, self.font_size)
        kr_font = _load_font(_KR_FONT_CANDIDATES, self.font_size)
        title_font = _load_font(_KR_FONT_CANDIDATES, self.font_size + 3)

        raw = text.replace("\t", "    ").split("\n")
        if len(raw) > 1 and raw[-1] == "":
            raw.pop()
        lines = raw

        content = {start_line + i for i, s in enumerate(lines) if s.strip()}
        hl = set(highlight_lines) if highlight_lines else set(ann_by_line.keys())
        hl &= content
        ann_by_line = {k: v for k, v in ann_by_line.items() if k in content}

        ascent = max(code_font.getmetrics()[0], kr_font.getmetrics()[0])
        descent = max(code_font.getmetrics()[1], kr_font.getmetrics()[1])
        line_pad = 8
        line_h = ascent + descent + line_pad
        pad = 18

        scratch = ImageDraw.Draw(PILImage.new("RGB", (1, 1)))
        char_w = scratch.textlength("M", font=code_font) or self.font_size * 0.6
        last_no = start_line + len(lines) - 1
        gutter_w = int(char_w * (len(str(last_no)) + 2))
        title_h = (line_h + pad) if title else 0

        def _font_for(s):
            return code_font if _is_ascii(s) else kr_font

        code_w = 0
        for s in lines:
            code_w = max(code_w, scratch.textlength(s, font=_font_for(s)))
        code_right = pad + gutter_w + int(code_w) + pad
        annot_w = 0
        for v in ann_by_line.values():
            annot_w = max(annot_w, scratch.textlength(">> " + v, font=kr_font))
        gap = 30
        annot_x = code_right + gap
        width = int(annot_x + annot_w + pad) if ann_by_line else int(code_right + pad)
        if title:
            width = max(width, int(pad + scratch.textlength(title, font=title_font) + pad))
        height = int(pad + title_h + len(lines) * line_h + pad)

        img = PILImage.new("RGB", (width, height), _D_BG)
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, pad + gutter_w - int(char_w / 2), height], fill=_D_GUTTER_BG)
        if title:
            draw.text((pad, pad), title, font=title_font, fill=_D_GREEN)

        top0 = pad + title_h
        line_top = {}
        for i, s in enumerate(lines):
            lineno = start_line + i
            top = top0 + i * line_h
            line_top[lineno] = top
            baseline = top + ascent
            num = str(lineno)
            nx = pad + gutter_w - int(char_w) - scratch.textlength(num, font=code_font)
            draw.text((nx, baseline), num, font=code_font, fill=_D_GUTTER_FG, anchor="ls")
            color = _D_GREEN if s.lstrip().startswith("#") else _D_FG
            draw.text((pad + gutter_w, baseline), s, font=_font_for(s), fill=color, anchor="ls")

        for lineno in sorted(hl):
            top = line_top[lineno] - 1
            bottom = line_top[lineno] + line_h - line_pad + 1
            draw.rectangle([pad + gutter_w - 4, top, code_right, bottom],
                           outline=_D_RED, width=2)

        for lineno, txt in ann_by_line.items():
            top = line_top[lineno]
            mid = top + (ascent + descent) // 2
            draw.line([code_right, mid, annot_x - 8, mid], fill=_D_CONNECT, width=1)
            draw.text((annot_x, top + ascent), ">> " + txt, font=kr_font,
                      fill=_D_GREEN, anchor="ls")

        self.outdir.mkdir(parents=True, exist_ok=True)
        stem = f"log-{abs(hash((text, title, tuple(sorted(ann_by_line.items()))))) & 0xffffffff:08x}"
        path = self.outdir / f"{stem}.png"
        img.save(path, "PNG")
        return str(path)

    # ---- flow diagram (class/function call flow) --------------------------
    @staticmethod
    def _parse_edge(s: str):
        """'src -> dst' (or 'src->dst') -> (src, dst); None if malformed."""
        for sep in ("->", "→"):
            if sep in s:
                a, b = s.split(sep, 1)
                return a.strip(), b.strip()
        return None

    def render_flow_diagram(
        self,
        nodes: list[str],
        edges: list[str],
        malicious: list[str] | None = None,
        aux: list[str] | None = None,
        title: str = "",
    ) -> str:
        """Render a class/function call-flow diagram (deterministic house style).

        nodes: 'id' or 'id|label' (label may contain '\\n' for multi-line).
        edges: 'src -> dst'. malicious/aux: node ids and/or 'src -> dst' edges to
        colour red / slate; edges between two malicious nodes turn red
        automatically. Layered top-down layout; returns the saved PNG path.
        """
        import math

        malicious = malicious or []
        aux = aux or []

        # -- parse nodes (preserve order) --
        labels: dict[str, str] = {}
        for item in nodes:
            nid, sep, lbl = item.partition("|")
            nid = nid.strip()
            if not nid:
                continue
            labels[nid] = (lbl.strip() if sep else nid)

        # -- parse edges; auto-add unknown endpoints so nothing is dropped --
        parsed: list[tuple[str, str]] = []
        for e in edges:
            pair = self._parse_edge(e)
            if not pair:
                continue
            for end in pair:
                labels.setdefault(end, end)
            parsed.append(pair)

        mal_nodes = {m.strip() for m in malicious if not self._parse_edge(m)}
        aux_nodes = {a.strip() for a in aux if not self._parse_edge(a)}
        mal_edges = {self._parse_edge(m) for m in malicious if self._parse_edge(m)}
        aux_edges = {self._parse_edge(a) for a in aux if self._parse_edge(a)}

        def node_kind(n):
            if n in mal_nodes:
                return "mal"
            if n in aux_nodes:
                return "aux"
            return "normal"

        def edge_kind(s, d):
            if (s, d) in mal_edges or (node_kind(s) == "mal" and node_kind(d) == "mal"):
                return "mal"
            if (s, d) in aux_edges or node_kind(s) == "aux" or node_kind(d) == "aux":
                return "aux"
            return "normal"

        # -- longest-path rank (bounded iterations => cycle-safe) --
        rank = {n: 0 for n in labels}
        for _ in range(len(labels)):
            changed = False
            for s, d in parsed:
                if rank[d] < rank[s] + 1:
                    rank[d] = rank[s] + 1
                    changed = True
            if not changed:
                break
        layers: dict[int, list[str]] = {}
        for n in labels:
            layers.setdefault(rank[n], []).append(n)

        fb = _load_font(_KR_FONT_CANDIDATES, 17)
        ft = _load_font(_KR_FONT_CANDIDATES, 20)
        fs = _load_font(_KR_FONT_CANDIDATES, 13)
        probe = ImageDraw.Draw(PILImage.new("RGB", (4, 4)))

        def measure(label):
            lines = label.split("\n")
            w = max(probe.textbbox((0, 0), ln, font=fb)[2] for ln in lines)
            lh = probe.textbbox((0, 0), "Ag힣", font=fb)[3] + 4
            return int(w + 36), int(lh * len(lines) + 22), lines, lh

        size = {n: measure(labels[n]) for n in labels}
        W = 980
        col_gap, row_gap, top = 54, 74, 76
        pos: dict[str, tuple] = {}
        y = top
        for r in sorted(layers):
            ns = layers[r]
            rw = sum(size[n][0] for n in ns) + col_gap * (len(ns) - 1)
            rh = max(size[n][1] for n in ns)
            x = (W - rw) / 2
            for n in ns:
                w, h = size[n][0], size[n][1]
                pos[n] = (x, y + (rh - h) / 2, w, h)
                x += w + col_gap
            y += rh + row_gap
        H = int(y - row_gap + 48)
        W = int(max(W, max((p[0] + p[2] for p in pos.values()), default=W) + 40))

        img = PILImage.new("RGB", (W, H), _F_BG)
        d = ImageDraw.Draw(img)
        if title:
            d.text((28, 24), title, font=ft, fill=_F_TITLE)
            d.line((28, 60, W - 28, 60), fill=_F_PANEL, width=2)

        def ctop(n): x, yy, w, h = pos[n]; return (x + w / 2, yy)
        def cbot(n): x, yy, w, h = pos[n]; return (x + w / 2, yy + h)

        def arrow(p1, p2, color, wd):
            d.line((*p1, *p2), fill=color, width=wd)
            a = math.atan2(p2[1] - p1[1], p2[0] - p1[0])
            for da in (2.6, -2.6):
                d.line((p2[0], p2[1], p2[0] - 12 * math.cos(a + da),
                        p2[1] - 12 * math.sin(a + da)), fill=color, width=wd)

        for s, dd in parsed:
            k = edge_kind(s, dd)
            arrow(cbot(s), ctop(dd), _F_EDGE[k], 3 if k == "mal" else 2)

        for n in labels:
            x, yy, w, h = pos[n]
            bc, fc = _F_KIND[node_kind(n)]
            d.rounded_rectangle((x, yy, x + w, yy + h), radius=9, fill=fc, outline=bc, width=2)
            _, _, lines, lh = size[n]
            ty = yy + (h - lh * len(lines)) / 2
            for ln in lines:
                b = probe.textbbox((0, 0), ln, font=fb)
                d.text((x + (w - (b[2] - b[0])) / 2, ty), ln, font=fb, fill=_F_INK)
                ty += lh

        ly = H - 30
        d.rounded_rectangle((28, ly, 46, ly + 13), radius=3,
                            fill=_F_KIND["mal"][1], outline=_F_KIND["mal"][0], width=2)
        d.text((52, ly - 3), "악성/위험 경로", font=fs, fill=_F_MUTE)
        d.rounded_rectangle((190, ly, 208, ly + 13), radius=3,
                            fill=_F_KIND["aux"][1], outline=_F_KIND["aux"][0], width=2)
        d.text((214, ly - 3), "보조/안전 경로", font=fs, fill=_F_MUTE)

        self.outdir.mkdir(parents=True, exist_ok=True)
        key = (tuple(nodes), tuple(edges), tuple(malicious), tuple(aux), title)
        stem = f"flow-{abs(hash(key)) & 0xffffffff:08x}"
        path = self.outdir / f"{stem}.png"
        img.save(path, "PNG")
        return str(path)
