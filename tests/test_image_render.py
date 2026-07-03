"""Tests for CodeImageRenderer (annotated code -> PNG)."""

import os
import sys

from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from imagerender import CodeImageRenderer, _merge_ranges, _tokenize_lines

_JAVA = '''// 기기 등록 도메인
public static final String url = "https://clearwatch.tv/a";
String msg = "인증 실패";
'''


class TestHelpers:
    def test_merge_ranges_collapses_consecutive(self):
        assert _merge_ranges([2, 3, 4, 8, 10, 11]) == [(2, 4), (8, 8), (10, 11)]

    def test_merge_ranges_empty(self):
        assert _merge_ranges([]) == []

    def test_merge_ranges_dedup_and_sort(self):
        assert _merge_ranges([5, 2, 2, 3]) == [(2, 3), (5, 5)]

    def test_tokenize_lines_count_and_segments(self):
        lines = _tokenize_lines(_JAVA, "java")
        assert len(lines) == 3
        # every segment is (color_tuple, text)
        for line in lines:
            for color, text in line:
                assert isinstance(color, tuple) and len(color) == 3
                assert isinstance(text, str)


class TestRender:
    def test_render_produces_png(self, tmp_path):
        r = CodeImageRenderer(output_dir=str(tmp_path))
        path = r.render_code_image(
            _JAVA, language="java",
            highlight_lines=[2, 3],
            annotations=[{"line": 2, "text": "C2 도메인"}],
            title="검증",
        )
        assert os.path.isfile(path)
        with Image.open(path) as im:
            assert im.format == "PNG"
            assert im.size[0] > 50 and im.size[1] > 20

    def test_render_ignores_bad_annotations(self, tmp_path):
        r = CodeImageRenderer(output_dir=str(tmp_path))
        # missing 'line'/'text' keys and non-int line must not crash
        path = r.render_code_image(
            _JAVA,
            annotations=[{"text": "no line"}, {"line": "x", "text": "bad"},
                         {"line": 2, "text": "ok"}],
        )
        assert os.path.isfile(path)

    def test_render_out_of_range_highlight_is_safe(self, tmp_path):
        r = CodeImageRenderer(output_dir=str(tmp_path))
        path = r.render_code_image(_JAVA, highlight_lines=[999])
        assert os.path.isfile(path)

    def test_render_unknown_language_falls_back(self, tmp_path):
        r = CodeImageRenderer(output_dir=str(tmp_path))
        path = r.render_code_image("some plain text\nsecond line",
                                   language="not-a-real-lexer")
        assert os.path.isfile(path)

    def test_blank_line_highlight_and_annotation_skipped(self, tmp_path):
        r = CodeImageRenderer(output_dir=str(tmp_path))
        # line 2 is blank -> highlighting/annotating it must not draw an empty
        # box; the render still succeeds.
        code = "int a = 1;\n\nint b = 2;\n"
        path = r.render_code_image(
            code, language="java", highlight_lines=[2],
            annotations=[{"line": 2, "text": "빈 줄"}, {"line": 1, "text": "ok"}])
        assert os.path.isfile(path)

    def test_start_line_offset(self, tmp_path):
        r = CodeImageRenderer(output_dir=str(tmp_path))
        # rendering a snippet that starts at line 100 should still work and
        # highlight by the displayed line number
        path = r.render_code_image(_JAVA, start_line=100, highlight_lines=[101])
        assert os.path.isfile(path)
