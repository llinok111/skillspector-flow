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

"""Renderers for the flow audit.

The audit is meant to be read by a human under time pressure: every finding
prints both ends of the relation and the sentence it came from, so the reader
can judge it without re-opening the skill.
"""

from __future__ import annotations

from skillspector.flow.bundle import BundleReport
from skillspector.flow.detect import SEVERITY_ORDER, Finding, FlowReport

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INCOMPLETE = 3


def exit_code(report: FlowReport, minimum: str) -> int:
    """Return the process exit code for one audit."""
    if not report.is_complete:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if report.at_or_above(minimum) else EXIT_CLEAN


def _counts(findings: tuple[Finding, ...]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _relation_line(finding: Finding) -> str:
    sink = finding.sink.text if finding.sink is not None else "(no destination)"
    return f"{finding.source.text}  ->  {sink}"


def render_terminal(report: FlowReport, minimum: str = "MEDIUM") -> str:
    """Plain-text report, safe to print on any console."""
    shown = report.at_or_above(minimum)
    counts = _counts(report.findings)
    lines = [
        "Flow audit: instruction-level data movement",
        f"  target     {report.target}",
        f"  inspected  {report.files_scanned} file(s), {report.bytes_scanned} byte(s), "
        f"{report.elapsed_ms} ms",
        f"  findings   {len(report.findings)} total "
        f"(HIGH {counts['HIGH']}, MEDIUM {counts['MEDIUM']}, LOW {counts['LOW']})",
        f"  highest    {report.highest()}",
    ]
    if report.limitations:
        lines.append(f"  incomplete {', '.join(report.limitations)}")
    lines.append("")

    if not shown:
        lines.append(f"No flow at or above {minimum}.")
        return "\n".join(lines)

    for finding in shown:
        lines.append(f"[{finding.severity}] {finding.rule} {finding.relation}")
        lines.append(f"  at        {finding.file}:{finding.line}")
        lines.append(f"  relation  {_relation_line(finding)}")
        lines.append(f"  why       {finding.explanation}")
        lines.append(f"  context   {finding.snippet}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(report: FlowReport, minimum: str = "MEDIUM") -> str:
    """Markdown report for pull-request comments and issue attachments."""
    shown = report.at_or_above(minimum)
    counts = _counts(report.findings)
    lines = [
        "# Flow audit",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Inspected:** {report.files_scanned} file(s), {report.bytes_scanned} byte(s)",
        f"- **Findings:** {len(report.findings)} "
        f"(HIGH {counts['HIGH']}, MEDIUM {counts['MEDIUM']}, LOW {counts['LOW']})",
        f"- **Highest:** {report.highest()}",
    ]
    if report.limitations:
        lines.append(f"- **Incomplete:** {', '.join(report.limitations)}")
    lines.append("")
    if not shown:
        lines.append(f"No flow at or above **{minimum}**.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Severity | Rule | Location | Source | Destination |",
            "|---|---|---|---|---|",
        ]
    )
    for finding in shown:
        sink = finding.sink.text if finding.sink is not None else "—"
        lines.append(
            f"| {finding.severity} | {finding.rule} | `{finding.file}:{finding.line}` | "
            f"`{finding.source.text}` | `{sink}` |"
        )
    lines.append("")
    for finding in shown:
        lines.append(f"### {finding.rule} · {finding.file}:{finding.line} · {finding.severity}")
        lines.append("")
        lines.append(finding.explanation)
        lines.append("")
        lines.append("```text")
        lines.append(finding.snippet)
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: FlowReport, minimum: str = "MEDIUM") -> dict[str, object]:
    """Machine-readable report; every field is derived, none is estimated."""
    counts = _counts(report.findings)
    return {
        "tool": "skillspector flow",
        "mode": "single",
        "target": report.target,
        "summary": {
            "files_scanned": report.files_scanned,
            "bytes_scanned": report.bytes_scanned,
            "elapsed_ms": report.elapsed_ms,
            "findings": len(report.findings),
            "by_severity": counts,
            "highest": report.highest(),
            "minimum_reported": minimum,
            "complete": report.is_complete,
        },
        "findings": [f.to_dict() for f in report.at_or_above(minimum)],
        "suppressed_by_threshold": len(report.findings) - len(report.at_or_above(minimum)),
        "limitations": list(report.limitations),
    }


def render_bundle_terminal(report: BundleReport, minimum: str = "MEDIUM") -> str:
    """Plain-text bundle report."""
    order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    per_skill = [r for _, r in report.skills]
    total = sum(len(r.findings) for r in per_skill)
    header = "  " + "skill".ljust(28) + " " + "findings".rjust(8) + "  highest"
    lines = [
        "Flow audit: skill pack",
        f"  target     {report.target}",
        f"  skills     {len(report.skills)}",
        f"  findings   {total} (per skill), {len(report.chains)} chain(s)",
        f"  highest    {report.highest()}",
        "",
        header,
    ]
    for name, flow in report.skills:
        lines.append(f"  {name[:28]:<28} {len(flow.findings):>8}  {flow.highest()}")
    lines.append("")
    for chain in report.chains:
        if order[chain.severity] < order[minimum]:
            continue
        lines.append(f"[{chain.severity}] {chain.rule} {chain.collector} + {chain.sender}")
        lines.append(f"  relation  {chain.source}  ->  {chain.sink}")
        lines.append(f"  why       {chain.explanation}")
        lines.append("")
    if not report.chains:
        lines.append("No cross-skill chains found.")
    return "\n".join(lines).rstrip() + "\n"


def render_bundle_json(report: BundleReport, minimum: str = "MEDIUM") -> dict[str, object]:
    """Machine-readable bundle report."""
    skill_findings = 0
    for _, flow in report.skills:
        skill_findings += len(flow.findings)
    return {
        "tool": "skillspector flow",
        "mode": "bundle",
        "target": report.target,
        "summary": {
            "skills": len(report.skills),
            "findings": skill_findings,
            "chains": len(report.chains),
            "highest": report.highest(),
            "minimum_reported": minimum,
            "complete": not report.limitations,
        },
        "skills": [
            {
                "name": name,
                "findings": [f.to_dict() for f in flow.at_or_above(minimum)],
                "highest": flow.highest(),
                "complete": flow.is_complete,
            }
            for name, flow in report.skills
        ],
        "chains": [c.to_dict() for c in report.chains],
        "limitations": list(report.limitations),
    }


def bundle_exit_code(report: BundleReport, minimum: str) -> int:
    """Exit code for a bundle audit: chains and per-skill findings both count."""
    order = SEVERITY_ORDER
    floor = order[minimum]
    if report.limitations:
        return EXIT_INCOMPLETE
    if any(order[c.severity] >= floor for c in report.chains):
        return EXIT_FINDINGS
    if any(order[f.severity] >= floor for _, flow in report.skills for f in flow.findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN
