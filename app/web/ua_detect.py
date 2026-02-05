from __future__ import annotations

from dataclasses import dataclass
from fastapi import Request


@dataclass(frozen=True)
class ClientProfile:
    """Simple UA-based device profile.

    Requirements:
    - Must be deterministic.
    - Must not rely on external services.
    - Used only to pick the best landing layout/CTA text.

    Note: We intentionally combine UA heuristics with responsive CSS on the frontend.
    Server-side detection only changes defaults (e.g. show APK install steps first).
    """

    kind: str  # "MOBILE" | "TABLET" | "DESKTOP"
    is_android: bool
    is_ios: bool


def _contains_any(s: str, needles: list[str]) -> bool:
    ls = s.lower()
    return any(n.lower() in ls for n in needles)


def detect_client_profile(user_agent: str | None) -> ClientProfile:
    """Detects client type from User-Agent.

    Rules (pragmatic):
    - iPad/tablet-like UA => TABLET.
    - Android + "mobile" => MOBILE.
    - Android without "mobile" => TABLET (common for some tablets).
    - Otherwise if general mobile indicators => MOBILE.
    - Else DESKTOP.

    This is a best-effort heuristic for content defaults.
    All critical flows must remain accessible regardless of detection.
    """

    ua = (user_agent or "").strip()
    if not ua:
        return ClientProfile(kind="DESKTOP", is_android=False, is_ios=False)

    ua_l = ua.lower()

    is_android = "android" in ua_l
    is_ios = _contains_any(ua_l, ["iphone", "ipad", "ipod"])

    # Tablet detection first
    if "ipad" in ua_l:
        return ClientProfile(kind="TABLET", is_android=False, is_ios=True)

    if is_android:
        # Many Android tablet UAs omit "mobile".
        if "mobile" in ua_l:
            return ClientProfile(kind="MOBILE", is_android=True, is_ios=False)
        return ClientProfile(kind="TABLET", is_android=True, is_ios=False)

    # Generic tablet indicators
    if _contains_any(
        ua_l,
        [
            "tablet",
            "kindle",
            "silk/",
            "playbook",
            "sm-t",  # Samsung tablets
            "nexus 7",
            "nexus 9",
            "xoom",
        ],
    ):
        return ClientProfile(kind="TABLET", is_android=False, is_ios=False)

    # Generic mobile indicators
    if _contains_any(
        ua_l,
        [
            "mobi",
            "iphone",
            "ipod",
            "windows phone",
            "blackberry",
            "opera mini",
            "opera mobi",
        ],
    ):
        return ClientProfile(kind="MOBILE", is_android=False, is_ios=is_ios)

    return ClientProfile(kind="DESKTOP", is_android=False, is_ios=is_ios)


def detect_client_kind(request: Request | None) -> str:
    """Compatibility wrapper returning only the kind string."""
    ua = None
    if request is not None:
        ua = request.headers.get("User-Agent")
    return detect_client_profile(ua).kind
