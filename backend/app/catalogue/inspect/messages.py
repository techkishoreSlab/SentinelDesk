"""One-line admin explanations for inspection and ingest failure codes."""

from __future__ import annotations

HINTS: dict[str, str] = {
    "UNSUPPORTED_TYPE": "Only .pkg, .dmg and .zip (containing one .app) are supported.",
    "TYPE_MISMATCH": "The file's contents don't match its extension. Blocked for safety.",
    "PACKAGE_TOO_LARGE": "The package is larger than the configured limit.",
    "PACKAGE_EMPTY": "The download or upload was empty.",
    "UNSIGNED_PACKAGE": "The package isn't signed with an Apple Developer ID. Blocked for safety.",
    "UNSIGNED_APP": "The app isn't signed with an Apple Developer ID. Blocked for safety.",
    "TEAM_ID_MISMATCH": "Signature doesn't match the expected publisher. Blocked for safety.",
    "NOT_DEVELOPER_ID": "Signed, but not with a Developer ID certificate.",
    "DMG_LICENSE_PROMPT": (
        "This DMG shows a license screen, so it can't be installed silently. "
        "Use the vendor's .pkg instead."
    ),
    "DMG_ENCRYPTED": "This DMG is password protected and can't be installed silently.",
    "DMG_UNREADABLE": (
        "The disk image couldn't be read. It may be damaged or use an unsupported format."
    ),
    "DMG_TOOL_UNAVAILABLE": "DMG inspection isn't available on this server (7-Zip missing).",
    "NO_APP_FOUND": "No .app or .pkg was found at the top level of the package.",
    "AMBIGUOUS_PAYLOAD": "The package contains several apps. Add a package with exactly one.",
    "PAYLOAD_NAME_REJECTED": "The app or package name contains characters that aren't allowed.",
    "SYMLINK_REJECTED": "The installable item is a symbolic link. Blocked for safety.",
    "ZIP_PATH_REJECTED": "The ZIP contains unsafe paths or links. Blocked for safety.",
    "ZIP_ENCRYPTED": "The ZIP is password protected.",
    "ZIP_BOMB_SUSPECTED": "The ZIP expands to an unreasonable size. Blocked for safety.",
    "ZIP_UNREADABLE": "The ZIP file couldn't be read.",
    "APP_INFO_MISSING": "The app has no Info.plist.",
    "APP_INFO_UNREADABLE": "The app's Info.plist couldn't be read.",
    "APP_EXECUTABLE_MISSING": "The app's main executable is missing.",
    "APP_MEMBER_TOO_LARGE": "A file inside the package is too large to inspect.",
    "IDENTIFIER_UNREADABLE": "No valid bundle or package identifier was found.",
    "VERSION_UNREADABLE": "No valid version number was found.",
    "ARCH_UNREADABLE": "Couldn't tell which Mac processors this app supports.",
    "PKG_UNREADABLE": "The installer package couldn't be read.",
    "INSPECT_TIMEOUT": "Inspection took too long and was stopped.",
    "INSPECT_RESOURCE_LIMIT": "Inspection hit a safety limit (memory or CPU) and was stopped.",
    "INSPECT_FAILED": "The package couldn't be inspected.",
    "INSPECT_BUSY": "Other packages are being inspected. Try again in a minute.",
    "URL_REJECTED": "Only public https download links are allowed.",
    "URL_UNREACHABLE": (
        "The download link couldn't be fetched. Check the URL, or try again — large apps "
        "can take a few minutes."
    ),
    "DRAFT_NOT_FOUND": "This review has gone. Start the add again.",
    "DRAFT_EXPIRED": "This review expired after an hour. Start the add again.",
    "PRESET_NOT_FOUND": "Unknown preset.",
    "MISSING_SOURCE": "Choose a preset, paste a link or upload a file.",
}


def hint_for(code: str) -> str:
    return HINTS.get(code, "The package couldn't be added.")
