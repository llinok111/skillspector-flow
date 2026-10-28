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

"""Instruction-level data-flow audit for agent skills.

Pattern analyzers answer "does this text contain a risky string?". This layer
answers "does this skill move something sensitive somewhere?", which is a
property of a relationship, not of a string: the sensitive half and the
outbound half are frequently in different sentences, and occasionally in
different skills.
"""

from __future__ import annotations

from skillspector.flow.bundle import BundleReport, Chain, analyze_bundle
from skillspector.flow.detect import Finding, FlowReport, analyze_path
from skillspector.flow.report import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_INCOMPLETE,
    bundle_exit_code,
    exit_code,
    render_bundle_json,
    render_bundle_terminal,
    render_json,
    render_markdown,
    render_terminal,
)

__all__ = [
    "EXIT_CLEAN",
    "EXIT_ERROR",
    "EXIT_FINDINGS",
    "EXIT_INCOMPLETE",
    "BundleReport",
    "Chain",
    "Finding",
    "FlowReport",
    "analyze_bundle",
    "analyze_path",
    "bundle_exit_code",
    "exit_code",
    "render_bundle_json",
    "render_bundle_terminal",
    "render_json",
    "render_markdown",
    "render_terminal",
]
