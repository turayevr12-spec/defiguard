"""Report renderers (JSON and Markdown)."""

from .json_report import render_json
from .markdown_report import render_markdown

__all__ = ["render_json", "render_markdown"]
