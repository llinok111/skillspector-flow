# SPDX-FileCopyrightText: Copyright (c) 2026 skillflow contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bounded file discovery and segmentation for the flow audit.

The audit needs two things the pattern scanner does not: the *unit* a sentence
belongs to (so a relation can span a paragraph) and the *line* every offset
came from (so evidence is reproducible). Both are produced here, under explicit
resource ceilings.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FLOW_FILES = 2_000
MAX_FLOW_FILE_BYTES = 512 * 1024
MAX_FLOW_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SEGMENT_CHARS = 64 * 1024

_SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        "vendor",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)

_SCRIPT_SUFFIXES = {
    ".py": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
}

_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*([\w.+-]*)")
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*)$")
_SENTENCE_BREAK = re.compile(r"(?<=[.!?。！？])\s+")
#: A list item or table row is its own instruction. Joining them into one
#: paragraph manufactures relations that no reader would ever infer (a table
#: row about "upload screenshots" next to an unrelated docs link).
_SELF_CONTAINED_LINE = re.compile(r"^\s{0,3}(?:[-*+]\s|\d{1,3}[.)]\s|\||>)")

_LANG_ALIASES = {
    "py": "python",
    "python": "python",
    "sh": "shell",
    "bash": "shell",
    "zsh": "shell",
    "shell": "shell",
    "console": "shell",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
    "node": "javascript",
}


@dataclass(frozen=True, slots=True)
class Segment:
    """One addressable chunk of a skill file."""

    file: str
    kind: str
    lang: str
    start_line: int
    text: str

    def line_of(self, offset: int) -> int:
        """Map a character offset inside ``text`` to a 1-based file line."""
        return self.start_line + self.text.count("\n", 0, offset)


@dataclass(frozen=True, slots=True)
class SkillFile:
    """A discovered file and its decoded text."""

    path: Path
    relative: str
    text: str

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    @property
    def is_markdown(self) -> bool:
        return self.suffix in {".md", ".markdown", ".mdx"}

    @property
    def script_language(self) -> str | None:
        return _SCRIPT_SUFFIXES.get(self.suffix)


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Resource ceilings and the reasons a scan may be incomplete."""

    files_seen: int = 0
    files_read: int = 0
    bytes_read: int = 0
    limitations: tuple[str, ...] = ()

    @property
    def is_complete(self) -> bool:
        return not self.limitations


class _Budget:
    """Mutable accounting for one discovery pass."""

    def __init__(self) -> None:
        self.files_seen = 0
        self.files_read = 0
        self.bytes_read = 0
        self.limitations: list[str] = []

    def note(self, reason: str) -> None:
        if reason not in self.limitations:
            self.limitations.append(reason)

    def frozen(self) -> ScanLimits:
        return ScanLimits(
            files_seen=self.files_seen,
            files_read=self.files_read,
            bytes_read=self.bytes_read,
            limitations=tuple(self.limitations),
        )


def _iter_candidates(root: Path, budget: _Budget) -> list[Path]:
    if root.is_file():
        budget.files_seen = 1
        return [root]

    candidates: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRECTORIES)
        for name in sorted(filenames):
            path = Path(current) / name
            suffix = path.suffix.lower()
            if suffix not in {".md", ".markdown", ".mdx", *_SCRIPT_SUFFIXES}:
                continue
            budget.files_seen += 1
            if budget.files_seen > MAX_FLOW_FILES:
                budget.note("file_count_limit")
                return candidates
            candidates.append(path)
    return candidates


def discover(root: Path) -> tuple[list[SkillFile], ScanLimits]:
    """Read every instruction-bearing file under ``root`` within the budget.

    ``SKILL.md`` is ordered first so its evidence wins when two files describe
    the same flow; the rest keep lexical order for reproducible output.
    """
    root = root.expanduser()
    budget = _Budget()
    candidates = _iter_candidates(root, budget)
    base = root.parent if root.is_file() else root

    ordered = sorted(
        candidates,
        key=lambda p: (0 if p.name.lower() == "skill.md" else 1, str(p).lower()),
    )

    files: list[SkillFile] = []
    for path in ordered:
        try:
            size = path.stat().st_size
        except OSError:
            budget.note("unreadable_file")
            continue
        if size > MAX_FLOW_FILE_BYTES:
            budget.note("file_size_limit")
            continue
        if budget.bytes_read + size > MAX_FLOW_TOTAL_BYTES:
            budget.note("total_size_limit")
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            budget.note("unreadable_file")
            continue
        budget.bytes_read += size
        budget.files_read += 1
        try:
            relative = path.relative_to(base).as_posix()
        except ValueError:
            relative = path.name
        files.append(SkillFile(path=path, relative=relative, text=text))
    return files, budget.frozen()


def _segments_from_markdown(file: SkillFile) -> list[Segment]:
    segments: list[Segment] = []
    paragraph: list[str] = []
    paragraph_start = 0

    def flush() -> None:
        nonlocal paragraph
        if paragraph:
            text = "\n".join(paragraph)
            segments.append(
                Segment(
                    file=file.relative,
                    kind="prose",
                    lang="",
                    start_line=paragraph_start,
                    text=text[:MAX_SEGMENT_CHARS],
                )
            )
            paragraph = []

    fence: str | None = None
    fence_lang = ""
    code_lines: list[str] = []
    code_start = 0

    lines = file.text.splitlines()
    first = 1
    # YAML front matter is metadata, not instruction. Reading it as prose glues
    # `name`/`description` onto the first paragraph and manufactures relations
    # that the agent never sees as a single instruction.
    if lines and lines[0].strip() in {"---", "+++"}:
        marker = lines[0].strip()
        for offset, candidate in enumerate(lines[1:], start=2):
            if candidate.strip() in {marker, "..."}:
                first = offset + 1
                break

    for number, raw in enumerate(lines[first - 1 :], start=first):
        line = raw.rstrip("\r")
        if fence is not None:
            closing = line.strip()
            if (
                closing.startswith(fence)
                and set(closing) <= {fence[0]}
                and len(closing) >= len(fence)
            ):
                segments.append(
                    Segment(
                        file=file.relative,
                        kind="code",
                        lang=fence_lang,
                        start_line=code_start,
                        text="\n".join(code_lines)[:MAX_SEGMENT_CHARS],
                    )
                )
                fence = None
                fence_lang = ""
                code_lines = []
            else:
                code_lines.append(line)
            continue

        opener = _FENCE.match(line)
        if opener is not None:
            flush()
            fence = opener.group(1)
            fence_lang = _LANG_ALIASES.get(opener.group(2).lower(), opener.group(2).lower())
            code_start = number + 1
            continue

        heading = _HEADING.match(line)
        if heading is not None:
            flush()
            segments.append(
                Segment(
                    file=file.relative,
                    kind="heading",
                    lang="",
                    start_line=number,
                    text=heading.group(2).strip(),
                )
            )
            continue

        if not line.strip():
            flush()
            continue

        if _SELF_CONTAINED_LINE.match(line):
            flush()
            paragraph_start = number
            paragraph.append(line.strip())
            flush()
            continue

        if not paragraph:
            paragraph_start = number
        paragraph.append(line)

    flush()
    if fence is not None and code_lines:
        segments.append(
            Segment(
                file=file.relative,
                kind="code",
                lang=fence_lang,
                start_line=code_start,
                text="\n".join(code_lines)[:MAX_SEGMENT_CHARS],
            )
        )
    return segments


def _segments_from_script(file: SkillFile) -> list[Segment]:
    language = file.script_language or ""
    return [
        Segment(
            file=file.relative,
            kind="code",
            lang=language,
            start_line=1,
            text=file.text[:MAX_SEGMENT_CHARS],
        )
    ]


def segments_for(file: SkillFile) -> list[Segment]:
    """Split one file into prose paragraphs, headings, and code blocks."""
    if file.is_markdown:
        return _segments_from_markdown(file)
    if file.script_language is not None:
        return _segments_from_script(file)
    return []


def sentences(segment: Segment) -> list[tuple[str, int]]:
    """Split a prose segment into ``(sentence, offset)`` pairs."""
    text = segment.text
    if not text:
        return []
    parts: list[tuple[str, int]] = []
    cursor = 0
    for match in _SENTENCE_BREAK.finditer(text):
        end = match.start()
        if end > cursor:
            parts.append((text[cursor:end], cursor))
        cursor = match.end()
    if cursor < len(text):
        parts.append((text[cursor:], cursor))
    return parts
