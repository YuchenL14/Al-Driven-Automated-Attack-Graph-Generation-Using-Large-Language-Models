"""
ingest.py -- Stage 2 of the pipeline: turn a source document into clean text.

A real incident report usually arrives as a PDF. markitdown converts it to
clean, LLM-ready text in one call. Plain-text and markdown files are read
directly. The output of this stage is a single string that the extraction
stage (Stage 3) will read.
"""

from __future__ import annotations

from pathlib import Path


def ingest(path: str | Path) -> str:
    """Return the clean text of a report at `path` (.pdf, .txt, .md, .docx...)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"report not found: {p}")

    suffix = p.suffix.lower()
    if suffix in {".txt", ".md"}:
        text = p.read_text(encoding="utf-8").strip()
        if not text:
            raise ValueError(f"report contains no text: {p}")
        return text

    # everything else (pdf, docx, html, pptx...) goes through markitdown
    from markitdown import MarkItDown
    md = MarkItDown(enable_plugins=False)
    result = md.convert(str(p))
    text = result.text_content.strip()
    if not text:
        raise ValueError(_no_text_message(p))
    return text


def _no_text_message(path: Path) -> str:
    """Explain an empty extraction in terms the reader can act on.

    A PDF whose pages are pictures of words is a routine input: printing a web
    page or scanning a document both produce one. It carries no text layer, so
    no extractor can read it and refusing is correct. Saying only that nothing
    was extracted leaves the reader unable to tell that from a broken file.
    """

    if path.suffix.lower() != ".pdf":
        return (
            f"no text could be extracted from {path.name}. The file may be "
            "empty or in a format this tool cannot read. Supply a PDF, TXT, "
            "or Markdown report."
        )

    detail = ""
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        pages = len(reader.pages)
        images = 0
        for page in reader.pages:
            resources = page.get("/Resources") or {}
            xobjects = resources.get("/XObject")
            if xobjects is None:
                continue
            try:
                xobjects = xobjects.get_object()
                if any(
                    xobjects[key].get_object().get("/Subtype") == "/Image"
                    for key in xobjects
                ):
                    images += 1
            except Exception:
                continue
        if images:
            detail = (
                f" Its {pages} page(s) contain images on {images} of them and "
                "no text at all, so the words are pixels rather than "
                "characters."
            )
    except Exception:
        detail = ""

    return (
        f"{path.name} contains no readable text.{detail} This happens when a "
        "web page or document is saved as a picture rather than as text. "
        "Two reliable ways to fix it: select the article text in the browser, "
        "paste it into a plain .txt file and upload that; or re-export the "
        "PDF with a tool that keeps a text layer, then confirm you can "
        "select and copy words inside the PDF before uploading it."
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python ingest.py <report.pdf|report.txt>")
        raise SystemExit(1)
    out = ingest(sys.argv[1])
    print(f"[ok] extracted {len(out)} characters")
    print("-" * 60)
    print(out[:800])
