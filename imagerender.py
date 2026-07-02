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
    def __init__(self, output_dir: str | None = None, font_size: int = 18) -> None:
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
