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

"""Bundle-level chains: skills that are only dangerous together.

A skill pack is installed into one agent, and the agent reads all of its
instructions in one context. A skill that only *collects* a credential and a
skill that only *posts somewhere* are each unremarkable; together they are an
exfiltration path no per-skill scan can see.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from skillspector.flow.detect import FlowReport, analyze_path
from skillspector.flow.lexicon import find_sinks, find_sources, is_relay_url
from skillspector.flow.units import discover, segments_for

MAX_BUNDLE_SKILLS = 200
MAX_BUNDLE_CHAINS = 100


@dataclass(frozen=True, slots=True)
class SkillSurface:
    """What one skill can reach, independent of how it is wired."""

    name: str
    path: Path
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    has_relation: bool

    @property
    def collects(self) -> bool:
        return bool(self.sources) and not self.sinks

    @property
    def sends(self) -> bool:
        return bool(self.sinks) and not self.sources


@dataclass(frozen=True, slots=True)
class Chain:
    """A cross-skill path from a collector to a sender."""

    rule: str
    severity: str
    collector: str
    sender: str
    source: str
    sink: str
    explanation: str

    def to_dict(self) -> dict[str, object]:
        """Serialise for the JSON report."""
        return {
            "rule": self.rule,
            "severity": self.severity,
            "collector": self.collector,
            "sender": self.sender,
            "source": self.source,
            "sink": self.sink,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class BundleReport:
    """Per-skill flow results plus the chains found between them."""

    target: str
    skills: tuple[tuple[str, FlowReport], ...]
    chains: tuple[Chain, ...]
    limitations: tuple[str, ...]

    def highest(self) -> str:
        """Return the most severe level in the pack, including chains."""
        order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        levels = [report.highest() for _, report in self.skills]
        levels.extend(chain.severity for chain in self.chains)
        if not levels:
            return "NONE"
        return max(levels, key=lambda level: order[level])


def _skill_directories(root: Path) -> list[Path]:
    if (root / "SKILL.md").exists():
        return [root]
    if not root.is_dir():
        return []
    found: list[Path] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if (child / "SKILL.md").exists():
            found.append(child)
    return found[:MAX_BUNDLE_SKILLS]


def _surface(name: str, path: Path) -> SkillSurface:
    sources: list[str] = []
    sinks: list[str] = []
    files, _ = discover(path)
    for file in files:
        for segment in segments_for(file):
            for atom in find_sources(segment.text):
                if atom.text not in sources:
                    sources.append(atom.text)
            for atom in find_sinks(segment.text):
                if atom.kind == "url" and atom.text not in sinks:
                    sinks.append(atom.text)
    report = analyze_path(path)
    return SkillSurface(
        name=name,
        path=path,
        sources=tuple(sources),
        sinks=tuple(sinks),
        has_relation=bool(report.findings),
    )


def analyze_bundle(root: Path) -> BundleReport:
    """Analyse every skill under ``root`` and pair collectors with senders."""
    root = root.expanduser()
    directories = _skill_directories(root)
    limitations: list[str] = []
    if not directories:
        limitations.append("no_skill_found")

    skills: list[tuple[str, FlowReport]] = []
    surfaces: list[SkillSurface] = []
    for directory in directories:
        name = directory.name if directory != root else root.name
        skills.append((name, analyze_path(directory)))
        surfaces.append(_surface(name, directory))

    chains: list[Chain] = []
    collectors = [s for s in surfaces if s.collects]
    senders = [s for s in surfaces if s.sends]
    for collector in collectors:
        for sender in senders:
            if collector.name == sender.name:
                continue
            for sink in sender.sinks:
                # A pack-level chain is only worth reporting when the sender
                # talks to a receive-only service: "post to our documented API"
                # is a different claim from "post to a webhook drop box".
                if not is_relay_url(sink):
                    continue
                chains.append(
                    Chain(
                        rule="F4",
                        severity="MEDIUM",
                        collector=collector.name,
                        sender=sender.name,
                        source=collector.sources[0],
                        sink=sink,
                        explanation=(
                            "Neither skill is a finding on its own: one only reads "
                            "sensitive material, the other only posts to a drop service. "
                            "Installed together in one agent they form an exfiltration path."
                        ),
                    )
                )
                if len(chains) >= MAX_BUNDLE_CHAINS:
                    limitations.append("chain_limit")
                    break
            if len(chains) >= MAX_BUNDLE_CHAINS:
                break
        if len(chains) >= MAX_BUNDLE_CHAINS:
            break

    return BundleReport(
        target=str(root),
        skills=tuple(skills),
        chains=tuple(chains),
        limitations=tuple(limitations),
    )
