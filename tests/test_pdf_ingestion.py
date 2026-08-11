"""The PDF leg of the pipeline, which every real report travels.

This file exists because the suite passed for a long time in an environment
where `markitdown` was not installed at all. The only ingest test used a .txt
file, and `ingest` returns from the text branch before the markitdown import
is reached, so nothing ever executed the line that every PDF upload executes.
The application was being run from a different interpreter that happened to
have the dependency, and the two environments could not disagree visibly.

A test that merely imports the package would have caught that. These go a
little further and put a real PDF through the real converter.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest import ingest  # noqa: E402


def _blank_pdf(directory: Path) -> Path:
    """A syntactically valid PDF with a page and no text layer.

    This is the shape a scanned report arrives in, and the shape the tool has
    to refuse in terms the reader can act on.
    """

    from pypdf import PdfWriter

    path = directory / "blank.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    with path.open("wb") as handle:
        writer.write(handle)
    return path


class PdfIngestionTests(unittest.TestCase):
    def test_the_pdf_converter_is_installed(self):
        # requirements.txt has asked for markitdown since the beginning. This
        # asserts the environment running the tests is the environment that
        # can run the application, which is the assumption that silently broke.
        try:
            import markitdown  # noqa: F401
        except ModuleNotFoundError as error:      # pragma: no cover
            self.fail(
                "markitdown is not installed, so no PDF can be ingested here "
                "even though requirements.txt asks for it. Install it with "
                f"pip install 'markitdown[pdf]'. Original error: {error}")

    def test_a_pdf_with_no_text_layer_is_refused_with_a_usable_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _blank_pdf(Path(directory))
            with self.assertRaises(ValueError) as caught:
                ingest(path)
        message = str(caught.exception).lower()
        # The reader has to be able to tell "this file carries pictures of
        # words" from "this file is broken", and be told what to do next.
        self.assertIn("no readable text", message)
        self.assertIn("picture", message)
        self.assertIn(path.name.lower(), message)

    def test_a_missing_report_is_named(self):
        with self.assertRaisesRegex(FileNotFoundError, "report not found"):
            ingest(Path("no-such-report.pdf"))

    def test_a_text_report_does_not_need_the_converter(self):
        # The fast path stays available, so a machine without the PDF extras
        # can still run the txt and md workflows.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            path.write_text("An attacker exploited an exposed service.\n",
                            encoding="utf-8")
            self.assertEqual(
                "An attacker exploited an exposed service.", ingest(path))


if __name__ == "__main__":
    unittest.main()
