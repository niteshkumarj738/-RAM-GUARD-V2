"""
run_dashboard_secure.py

Launches the RAM-Guard dashboard exactly like `streamlit run dashboard.py`
does, but first patches Streamlit's internal middleware stack to add
standard HTTP security headers to every response -- Streamlit sets none
of these by default, and there's no public config option for them
(confirmed by reading Streamlit's own source). This patches the one
documented internal function (create_streamlit_middleware) that builds
the middleware list before the app starts, rather than editing
Streamlit's own installed files, which would be lost on any upgrade.

Uses a raw ASGI middleware (not Starlette's BaseHTTPMiddleware) that
passes non-HTTP scopes straight through untouched -- Streamlit's live
updates depend on a WebSocket connection, which BaseHTTPMiddleware is
known to interfere with.

Usage:
    python run_dashboard_secure.py
"""

import sys
from pathlib import Path

from starlette.datastructures import MutableHeaders
from starlette.middleware import Middleware


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_static = scope["path"].startswith("/static/") or scope["path"] == "/favicon.png"

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'sha256-THxz9J9+wf7rhwR2YkXJoSZ13UCmYyC+3lNDv2+8ugA='; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data: blob:; "
                    "font-src 'self' data:; "
                    "connect-src 'self'; "
                    "object-src 'none'; base-uri 'self'; form-action 'self'; "
                    "frame-ancestors 'none'"
                )
                headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
                headers["Cross-Origin-Resource-Policy"] = "same-origin"
                headers["Cross-Origin-Embedder-Policy"] = "credentialless"
                headers["Cross-Origin-Opener-Policy"] = "same-origin"
                if is_static:
                    # Content-hashed static assets: cache aggressively, and drop
                    # the validators Streamlit sets by default -- ETag/Last-Modified
                    # alongside a long immutable max-age is a redundant/conflicting
                    # signal that a cache-policy scanner flags either way.
                    headers["Cache-Control"] = "public, max-age=31536000, immutable"
                    del headers["etag"]
                    del headers["last-modified"]
                else:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_wrapper)


def _patch_streamlit_headers():
    from streamlit.web.server.starlette import starlette_app

    original_create_middleware = starlette_app.create_streamlit_middleware

    def patched_create_middleware():
        middleware = original_create_middleware()
        middleware.append(Middleware(SecurityHeadersMiddleware))
        return middleware

    starlette_app.create_streamlit_middleware = patched_create_middleware


if __name__ == "__main__":
    _patch_streamlit_headers()
    sys.argv = ["streamlit", "run", str(Path(__file__).parent / "dashboard.py")]
    from streamlit.web.cli import main
    main()
