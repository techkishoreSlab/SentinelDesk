"""Curated, code-reviewed one-click catalogue presets.

Download URLs and Apple Developer Team IDs follow the matching Installomator labels. Nothing
is fetched at runtime except the package itself, and inspection re-checks the Team ID on every
add: a preset whose download is signed by anyone else fails closed with TEAM_ID_MISMATCH.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.db.enums import RiskLevel


@dataclass(frozen=True, slots=True)
class Preset:
    id: str
    name: str
    slug: str
    publisher: str
    category: str
    risk: RiskLevel
    kind: str
    team_id: str
    # Architecture -> https URL. "universal" when one download serves both.
    urls: dict[str, str]
    aliases: tuple[str, ...] = ()
    require_approval: bool = True
    description: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)


PRESETS: tuple[Preset, ...] = (
    Preset(
        id="slack",
        name="Slack",
        slug="slack",
        publisher="Slack Technologies",
        category="communication",
        risk=RiskLevel.LOW,
        kind="MACOS_DMG_APP",
        team_id="BQR82RBBHL",
        urls={
            "universal": (
                "https://slack.com/api/desktop.latestRelease?redirect=1&variant=dmg&arch=universal"
            )
        },
        aliases=("slack", "slack desktop"),
        description="Team chat and calls.",
    ),
    Preset(
        id="google-chrome",
        name="Google Chrome",
        slug="google-chrome",
        publisher="Google",
        category="browser",
        risk=RiskLevel.LOW,
        kind="MACOS_DMG_APP",
        team_id="EQHXZ8M8AV",
        urls={
            "universal": "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg"
        },
        aliases=("chrome", "google chrome"),
        description="Web browser.",
    ),
    Preset(
        id="firefox",
        name="Firefox",
        slug="firefox",
        publisher="Mozilla",
        category="browser",
        risk=RiskLevel.LOW,
        kind="MACOS_DMG_APP",
        team_id="43AQ936H96",
        urls={
            "universal": "https://download.mozilla.org/?product=firefox-latest&os=osx&lang=en-US"
        },
        aliases=("firefox", "mozilla firefox"),
        description="Web browser.",
    ),
    Preset(
        id="zoom",
        name="Zoom",
        slug="zoom",
        publisher="Zoom Video Communications",
        category="communication",
        risk=RiskLevel.LOW,
        kind="MACOS_PKG",
        team_id="BJ4HAAB9B3",
        urls={"universal": "https://zoom.us/client/latest/ZoomInstallerIT.pkg"},
        aliases=("zoom", "zoom meetings"),
        description="Video meetings (IT installer package).",
    ),
    Preset(
        id="visual-studio-code",
        name="Visual Studio Code",
        slug="visual-studio-code",
        publisher="Microsoft",
        category="developer-tools",
        risk=RiskLevel.LOW,
        kind="MACOS_ZIP_APP",
        team_id="UBF8T346G9",
        urls={"universal": "https://update.code.visualstudio.com/latest/darwin-universal/stable"},
        aliases=("vs code", "vscode", "visual studio code", "code"),
        description="Code editor.",
    ),
    Preset(
        id="nodejs-lts",
        name="Node.js LTS",
        slug="nodejs",
        publisher="OpenJS Foundation",
        category="developer-tools",
        risk=RiskLevel.MEDIUM,
        kind="MACOS_PKG",
        team_id="HX7739G8FX",
        urls={"universal": "https://nodejs.org/dist/v24.22.3/node-v24.22.3.pkg"},
        aliases=("node", "nodejs", "node.js"),
        description="JavaScript runtime (pinned LTS release).",
    ),
    Preset(
        id="postman",
        name="Postman",
        slug="postman",
        publisher="Postman",
        category="developer-tools",
        risk=RiskLevel.LOW,
        kind="MACOS_ZIP_APP",
        team_id="H7H8Q7M5CK",
        urls={
            "arm64": "https://dl.pstmn.io/download/latest/osx_arm64",
            "x86_64": "https://dl.pstmn.io/download/latest/osx_64",
        },
        aliases=("postman",),
        description="API client. Separate Apple silicon and Intel downloads.",
    ),
)

_BY_ID = {p.id: p for p in PRESETS}


def get_preset(preset_id: str) -> Preset | None:
    return _BY_ID.get(preset_id)


def preset_url(preset: Preset, architecture: str | None) -> tuple[str, str]:
    """Return (architecture key, url). Defaults to the first listed download."""
    if architecture and architecture in preset.urls:
        return architecture, preset.urls[architecture]
    key = next(iter(preset.urls))
    return key, preset.urls[key]
