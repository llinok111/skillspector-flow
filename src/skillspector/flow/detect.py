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

"""Instruction-level data-flow detection.

A skill's *instructions* are executable: the agent reads the markdown and does
what it says. Pattern rules look for risky strings; this module looks for a
risky *relationship* - a sensitive source, an outbound destination, and a
transfer that connects them - and reports it with both ends as evidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from skillspector.flow.lexicon import (
    AtomMatch,
    CodeSignals,
    find_sinks,
    find_sources,
    has_carrier,
    has_transfer_verb,
    is_negated,
)
from skillspector.flow.units import (
    ScanLimits,
    Segment,
    SkillFile,
    discover,
    segments_for,
    sentences,
)

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_CONFIDENCE = {"LOW": 0.4, "MEDIUM": 0.65, "HIGH": 0.9}

MAX_FLOW_FINDINGS = 500
MAX_FLOW_SECONDS = 30.0

#: How far apart a source and its sink may sit and still count as one relation.
MAX_CARRIER_DISTANCE_SENTENCES = 2


@dataclass(frozen=True, slots=True)
class Finding:
    """One source-to-sink relation, with reproducible evidence."""

    rule: str
    severity: str
    file: str
    line: int
    relation: str
    source: AtomMatch
    sink: AtomMatch | None
    explanation: str
    snippet: str

    @property
    def confidence(self) -> float:
        return _CONFIDENCE[self.severity]

    def to_dict(self) -> dict[str, object]:
        """Serialise for the JSON report."""
        return {
            "rule": self.rule,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "relation": self.relation,
            "source": {
                "kind": self.source.kind,
                "label": self.source.label,
                "text": self.source.text,
            },
            "sink": (
                None if self.sink is None else {"kind": self.sink.kind, "text": self.sink.text}
            ),
            "explanation": self.explanation,
            "snippet": self.snippet,
        }


@dataclass(frozen=True, slots=True)
class FlowReport:
    """Everything one flow audit produced."""

    target: str
    findings: tuple[Finding, ...]
    files_scanned: int
    bytes_scanned: int
    limitations: tuple[str, ...]
    elapsed_ms: int

    @property
    def is_complete(self) -> bool:
        return not self.limitations

    def at_or_above(self, minimum: str) -> tuple[Finding, ...]:
        """Return findings whose severity is at least ``minimum``."""
        floor = SEVERITY_ORDER[minimum]
        return tuple(f for f in self.findings if SEVERITY_ORDER[f.severity] >= floor)

    def highest(self) -> str:
        """Return the most severe level present, or ``NONE``."""
        if not self.findings:
            return "NONE"
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])


def _severity(source: AtomMatch, sink: AtomMatch | None) -> str:
    strong_source = source.tier == "strong"
    concrete_sink = sink is not None and sink.kind == "url"
    if strong_source and concrete_sink:
        return "HIGH"
    if strong_source or concrete_sink:
        return "MEDIUM"
    return "LOW"


def _snippet(segment: Segment, offset: int, limit: int = 180) -> str:
    text = segment.text
    start = max(0, offset - 40)
    end = min(len(text), offset + limit)
    return text[start:end].replace("\n", " ").strip()


def _finding(
    rule: str,
    segment: Segment,
    source: AtomMatch,
    sink: AtomMatch | None,
    relation: str,
    explanation: str,
    *,
    severity: str | None = None,
    offset: int | None = None,
) -> Finding:
    line = segment.line_of(source.start if offset is None else offset)
    return Finding(
        rule=rule,
        severity=severity or _severity(source, sink),
        file=segment.file,
        line=line,
        relation=relation,
        source=source,
        sink=sink,
        explanation=explanation,
        snippet=_snippet(segment, source.start),
    )


def _analyze_prose(segment: Segment, out: list[Finding]) -> None:
    pieces = sentences(segment)
    if not pieces:
        return

    sentence_atoms: list[tuple[str, int, list[AtomMatch], list[AtomMatch]]] = []
    for text, offset in pieces:
        sentence_atoms.append((text, offset, find_sources(text), find_sinks(text)))

    for index, (text, offset, sources, sinks) in enumerate(sentence_atoms):
        if not sources:
            continue
        if is_negated(text):
            continue

        # F1: the sentence itself names source, destination, and the transfer.
        if sinks and has_transfer_verb(text):
            for source in sources[:1]:
                out.append(
                    _finding(
                        "F1",
                        segment,
                        source,
                        sinks[0],
                        "same-sentence",
                        "One instruction names a sensitive source, a network "
                        "destination, and the verb that moves one to the other.",
                        offset=offset + source.start,
                    )
                )
            continue

        # F2: the next sentence carries the payload on, naming it by reference.
        following = sentence_atoms[index + 1 : index + 1 + MAX_CARRIER_DISTANCE_SENTENCES]
        for follow_text, _follow_offset, follow_sources, follow_sinks in following:
            if follow_sources or not follow_sinks:
                continue
            if not has_transfer_verb(follow_text) or not has_carrier(follow_text):
                continue
            if is_negated(follow_text):
                continue
            out.append(
                _finding(
                    "F2",
                    segment,
                    sources[0],
                    follow_sinks[0],
                    "carrier-pronoun",
                    "A sensitive source is named here and the following "
                    "instruction forwards 'it' to a network destination.",
                    severity="MEDIUM" if sources[0].tier == "strong" else "LOW",
                    offset=offset + sources[0].start,
                )
            )
            break


_AUTH_CONTEXT = ("authorization", "bearer", "x-api-key", "api_key_header")


def _payload_context(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "data=",
            "json=",
            "files=",
            "body:",
            "body=",
            "--data",
            "-d ",
            "--form",
            "-f ",
        )
    )


def _auth_only(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _AUTH_CONTEXT) and not _payload_context(text)


def _analyze_code(segment: Segment, out: list[Finding]) -> None:
    text = segment.text
    sources = find_sources(text)
    if not sources:
        return
    urls = [sink for sink in find_sinks(text) if sink.kind == "url"]
    network = (
        CodeSignals.python_network.search(text)
        or CodeSignals.js_network.search(text)
        or CodeSignals.shell_upload.search(text)
    )
    if network is None or not urls:
        return

    for source in sources[:1]:
        statement_start = text.rfind("\n", 0, source.start) + 1
        statement_end = text.find("\n", source.start)
        end = statement_end if statement_end != -1 else len(text)
        statement = text[statement_start:end]
        if _auth_only(statement):
            continue
        if not (_payload_context(statement) or CodeSignals.shell_upload.search(statement)):
            continue
        # Report the destination this statement talks to. A block can mention
        # several URLs (docs links, a second example), and pairing the payload
        # with the wrong one makes the evidence unreadable.
        in_statement = [url for url in urls if statement_start <= url.start <= end]
        destination = min(in_statement or urls, key=lambda url: abs(url.start - source.start))
        out.append(
            _finding(
                "F3",
                segment,
                source,
                destination,
                "code-transfer",
                "Code reads a sensitive source and a network call in the same "
                "statement carries it out.",
                severity="HIGH",
                offset=source.start,
            )
        )
        break


def analyze_path(target: Path) -> FlowReport:
    """Audit one skill directory (or file) for source-to-sink relations."""
    started = time.monotonic()
    files, limits = discover(target)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    for file in files:
        if len(findings) >= MAX_FLOW_FINDINGS:
            limits = ScanLimits(
                files_seen=limits.files_seen,
                files_read=limits.files_read,
                bytes_read=limits.bytes_read,
                limitations=(*limits.limitations, "finding_limit"),
            )
            break
        if time.monotonic() - started > MAX_FLOW_SECONDS:
            limits = ScanLimits(
                files_seen=limits.files_seen,
                files_read=limits.files_read,
                bytes_read=limits.bytes_read,
                limitations=(*limits.limitations, "time_limit"),
            )
            break
        produced: list[Finding] = []
        for segment in segments_for(file):
            if segment.kind == "prose":
                _analyze_prose(segment, produced)
            elif segment.kind == "code":
                _analyze_code(segment, produced)
        for finding in produced:
            # The same relation restated later in the file is still one
            # relation: identity is source + destination, not line number.
            key = (
                finding.rule,
                finding.file,
                finding.source.text.casefold(),
                finding.sink.text.casefold() if finding.sink is not None else "",
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return FlowReport(
        target=str(target),
        findings=tuple(findings),
        files_scanned=limits.files_read,
        bytes_scanned=limits.bytes_read,
        limitations=limits.limitations,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def read_skill_files(target: Path) -> list[SkillFile]:
    """Expose discovery to the bundle analysis and to tests."""
    files, _ = discover(target)
    return files
