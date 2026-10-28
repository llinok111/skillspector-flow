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

"""Lexicons for the instruction-level data-flow audit.

Every entry is a deliberately narrow, textual signal. A source alone is not a
finding, a sink alone is not a finding: only a *directed relation* between the
two inside one skill is reported. The vocabularies below are case-insensitive
and never match across line breaks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- sources ---------------------------------------------------------------

#: Files whose content is a credential by construction. Matching these is what
#: separates "the user asked for a summary" from "the skill wants the keys".
_CREDENTIAL_PATH = re.compile(
    r"(?:"
    r"~?/\.ssh/[\w.-]+"
    r"|\.aws/credentials"
    r"|\.aws/config"
    r"|\.config/gh/hosts\.ya?ml"
    r"|\.docker/config\.json"
    r"|\.kube/config"
    r"|\.git-credentials"
    r"|\.netrc"
    r"|\.npmrc"
    r"|\.pgpass"
    r"|\.pypirc"
    r"|\bid_rsa\b"
    r"|\bid_ed25519\b"
    r"|\bid_ecdsa\b"
    r"|\bcredentials\.json\b"
    r"|\bservice-account[\w.-]*\.json\b"
    r"|\bwallet\.dat\b"
    r"|[\w.-]+\.(?:pem|p12|pfx)\b"
    r"|(?:^|[\s`'\"(（@=:])\.env(?:\.[\w-]+)?\b"
    r")",
    re.IGNORECASE,
)

#: Secret-bearing environment variables. ``*_TOKEN`` style names are matched by
#: the generic branch, but only when the suffix is one of the secret families.
_SECRET_ENV = re.compile(
    r"\b(?:"
    r"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ACCESS_KEY_ID"
    r"|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|DOCKER_PASSWORD"
    r"|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|HF_TOKEN"
    r"|SLACK_(?:BOT_)?TOKEN|DISCORD_(?:BOT_)?TOKEN|STRIPE_(?:SECRET|LIVE)_KEY"
    r"|[\w]+(?:_|^)(?:SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY|CREDENTIALS)"
    r")\b",
)

#: Private data that is not a file: conversation state, session material, and
#: anything a user would not expect to leave the machine.
_PRIVATE_DATA = re.compile(
    r"\b(?:"
    r"conversation (?:history|log|transcript)s?"
    r"|chat (?:history|log|transcript)s?"
    r"|message (?:history|log)s?"
    r"|session (?:history|transcript)s?"
    r"|browser (?:history|cookies?)"
    r"|saved (?:passwords?|credentials?)"
    r"|password manager|keychain|keyring"
    r"|clipboard (?:contents?|history)"
    r"|keystrokes?"
    r"|seed phrase|recovery phrase|mnemonic"
    r"|one[- ]time (?:code|password)s?|2fa code|otp code"
    r"|private key|ssh key|access tokens?|refresh tokens?|api keys?"
    r")\b",
    re.IGNORECASE,
)

#: Weak sources: sensitive-ish, often legitimately shared. They only escalate
#: to MEDIUM when paired with a concrete network destination.
_WEAK_SOURCE = re.compile(
    r"\b(?:"
    r"screen ?shots?|screen contents?|recordings? of the screen"
    r"|contact lists?|address books?"
    r"|email (?:messages?|inbox|threads?)"
    r"|calendar events?|location history"
    r"|purchase history|browsing (?:activity|data)"
    r")\b",
    re.IGNORECASE,
)

# --- sinks -----------------------------------------------------------------

_URL = re.compile(
    r"\bhttps?://[^\s`'\"<>()\[\]{}，。）】]+",
    re.IGNORECASE,
)

#: Hosts whose only purpose is receiving data from somewhere else.
_RELAY_HOSTS = (
    "webhook.site",
    "pipedream.net",
    "requestbin",
    "requestcatcher",
    "transfer.sh",
    "0x0.st",
    "file.io",
    "bashupload.com",
    "pastebin.com",
    "gofile.io",
    "ngrok.io",
    "ngrok-free.app",
    "hooks.slack.com",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org",
    "interact.sh",
    "oast.fun",
    "burpcollaborator.net",
)

#: A destination that is not pinned to a host. Weaker than a literal URL but
#: still directional: "send it to an external server" has no benign reading
#: when the payload is a credential.
_OPEN_ENDPOINT = re.compile(
    r"\b(?:"
    r"any (?:https? )?(?:url|endpoint|server|host)"
    r"|an? (?:external|remote|arbitrary|third[- ]party) (?:url|endpoint|server|host|service|api)"
    r"|attacker(?:'s)? (?:server|endpoint|host)"
    r"|webhooks?"
    r")\b",
    re.IGNORECASE,
)

# --- relations -------------------------------------------------------------

#: Verbs that move bytes from here to there. Kept verb-agnostic on purpose:
#: upstream's E1 only fires when a *command* carries the payload, so prose that
#: says "upload the .env file to ..." never reaches it.
_TRANSFER_VERB = re.compile(
    r"\b(?:"
    r"send|sends|sending|sent"
    r"|post|posts|posting"
    r"|upload|uploads|uploading"
    r"|publish|publishes|publishing"
    r"|forward|forwards|forwarding"
    r"|transmit|transmits|transmitting"
    r"|sync|syncs|syncing|synchroni[sz]e"
    r"|attach|attaches|attaching"
    r"|exfiltrate|exfiltrating|leak|leaks|leaking"
    r"|share|shares|sharing"
    r"|submit|submits|submitting"
    r"|push|pushes|pushing"
    r"|beam|beams|beaming"
    r")\b",
    re.IGNORECASE,
)

#: What the verb is carrying when the payload is not named again. Only true
#: anaphora counts: "the files" or "the report" describe *any* noun and would
#: link unrelated sentences.
_CARRIER = re.compile(
    r"\b(?:"
    r"it|them|they|these|those|this|that"
    r"|its contents?|their contents?"
    r"|the contents?|the data|the payload"
    r")\b",
    re.IGNORECASE,
)

#: Negated instructions are advice *against* the flow. Skip them: "never send
#: the .env file anywhere" must not be reported as an exfiltration path.
_NEGATION = re.compile(
    r"(?:\b(?:"
    r"never|must not|should not|do not|don't|avoid|avoiding|refuse|refusing"
    r"|without (?:sending|uploading|sharing|posting)"
    r")\b"
    r"|\bno\b[^.;]{0,60}\b(?:is|are|will be|gets|get)\b[^.;]{0,30}"
    r"\b(?:sent|uploaded|posted|shared|transmitted|forwarded|published)\b"
    r"|禁止|不要|不得|切勿|严禁)",
    re.IGNORECASE,
)

#: Destinations that never leave the machine. A loopback address is not egress,
#: and treating it as one turns every local API example into a finding.
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "://::1")

# --- code-level sinks ------------------------------------------------------

_PY_NETWORK_CALL = re.compile(
    r"\b(?:requests\.(?:post|put|patch)|httpx\.(?:post|put|patch)|urlopen|urlretrieve"
    r"|http\.client|aiohttp\.ClientSession)\b|\.(?:post|put|patch)\s*\(",
)
_PY_READ_SOURCE = re.compile(
    r"(?:open|read_text|read_bytes|Path)\(\s*[rbf]?['\"]([^'\"]+)['\"]",
)
_JS_NETWORK_CALL = re.compile(r"\bfetch\s*\(|axios\.(?:post|put)|\.sendBeacon\s*\(")
_SHELL_UPLOAD = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?(?:--data-binary|--post-file|--data\b|--data-raw|-d\b|-F\b|--form\b|--upload-file|-T\b)",
    re.IGNORECASE,
)
_FILE_REF = re.compile(r"@['\"]?([\w./~$-]+)|(?:open|cat)\s*\(?\s*['\"]?([\w./~$-]+)")


@dataclass(frozen=True, slots=True)
class AtomMatch:
    """One lexical hit, with the exact span it came from."""

    kind: str
    label: str
    tier: str
    text: str
    start: int
    end: int


_LEADING_SEPARATOR = " \t`'\"(（[@=:"


def _trim(text: str, start: int, end: int) -> tuple[str, int, int]:
    """Drop the delimiter a pattern needed in order to anchor itself."""
    while start < end and text[start] in _LEADING_SEPARATOR:
        start += 1
    while end > start and text[end - 1] in " \t.,;，。":
        end -= 1
    return text[start:end], start, end


def find_sources(text: str) -> list[AtomMatch]:
    """Return every sensitive source mentioned in ``text``, in order."""
    found: list[AtomMatch] = []
    for match in _CREDENTIAL_PATH.finditer(text):
        value, start, end = _trim(text, match.start(), match.end())
        if not value:
            continue
        found.append(
            AtomMatch(
                kind="credential",
                label="credential file",
                tier="strong",
                text=value,
                start=start,
                end=end,
            )
        )
    for match in _SECRET_ENV.finditer(text):
        found.append(
            AtomMatch(
                kind="secret-env",
                label="secret environment variable",
                tier="strong",
                text=match.group(0),
                start=match.start(),
                end=match.end(),
            )
        )
    for match in _PRIVATE_DATA.finditer(text):
        found.append(
            AtomMatch(
                kind="private-data",
                label="private user data",
                tier="strong",
                text=match.group(0),
                start=match.start(),
                end=match.end(),
            )
        )
    for match in _WEAK_SOURCE.finditer(text):
        found.append(
            AtomMatch(
                kind="weak-data",
                label="user content",
                tier="weak",
                text=match.group(0),
                start=match.start(),
                end=match.end(),
            )
        )
    return sorted(found, key=lambda atom: atom.start)


def find_sinks(text: str) -> list[AtomMatch]:
    """Return every outbound destination mentioned in ``text``, in order."""
    found: list[AtomMatch] = []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,;:!?\"'`")
        lowered = url.lower()
        if not url or any(local in lowered for local in _LOCAL_HOSTS):
            continue
        found.append(
            AtomMatch(
                kind="url",
                label="network destination",
                tier="strong",
                text=url,
                start=match.start(),
                end=match.start() + len(url),
            )
        )
    for match in _OPEN_ENDPOINT.finditer(text):
        found.append(
            AtomMatch(
                kind="open-endpoint",
                label="unspecified remote destination",
                tier="weak",
                text=match.group(0),
                start=match.start(),
                end=match.end(),
            )
        )
    return sorted(found, key=lambda atom: atom.start)


def is_negated(text: str) -> bool:
    """Return whether the sentence advises against the transfer."""
    return _NEGATION.search(text) is not None


def has_transfer_verb(text: str) -> bool:
    """Return whether the sentence moves data somewhere."""
    return _TRANSFER_VERB.search(text) is not None


def has_carrier(text: str) -> bool:
    """Return whether the sentence refers back to a payload already named."""
    return _CARRIER.search(text) is not None


def is_relay_url(url: str) -> bool:
    """Return whether ``url`` points at a receive-only drop service."""
    lowered = url.lower()
    return any(host in lowered for host in _RELAY_HOSTS)


class CodeSignals:
    """Pre-compiled code-level signals, exposed for the detectors and tests."""

    python_network = _PY_NETWORK_CALL
    python_read = _PY_READ_SOURCE
    js_network = _JS_NETWORK_CALL
    shell_upload = _SHELL_UPLOAD
    file_ref = _FILE_REF
