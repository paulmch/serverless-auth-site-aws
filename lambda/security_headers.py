"""Shared HTTP security headers for Lambda responses.

Every Lambda in this project previously carried its own near-identical copy of
`get_security_headers()`, which drifted (some included Cache-Control, some did
not). They all import from here instead - all handlers ship in the same asset
directory, so a plain module import works.
"""

from typing import Dict

# Content Security Policy for HTML responses produced by Lambda (the OAuth error
# pages). Those pages are plain HTML with no scripts, styles or images of their
# own, so everything can be denied outright.
#
# The authenticated index.html is served straight from S3 through API Gateway
# and gets its own, slightly wider policy from the stack, because it loads
# css/style.css and js/app.js.
HTML_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

# Content Security Policy for JSON API responses. Nothing should ever be
# rendered from these, so deny every fetch directive.
JSON_CONTENT_SECURITY_POLICY = "default-src 'none'; frame-ancestors 'none'"


def get_security_headers(
    content_security_policy: str = JSON_CONTENT_SECURITY_POLICY,
    cache: bool = False,
) -> Dict[str, str]:
    """Return security headers following OWASP guidance.

    Args:
        content_security_policy: CSP to send. Defaults to the JSON API policy.
        cache: When False (the default) the response is marked non-cacheable.
            Authenticated responses must not be stored by shared caches.

    CORS headers are deliberately absent: the frontend is served from this same
    API Gateway origin, so every browser request is same-origin.
    """
    headers = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': content_security_policy,
        # Explicitly disabled rather than omitted. The legacy XSS auditor this
        # header controlled introduced vulnerabilities of its own and has been
        # removed from current browsers; OWASP recommends sending 0. CSP above
        # is what actually provides the protection.
        'X-XSS-Protection': '0',
    }

    if not cache:
        headers['Cache-Control'] = 'no-store'
        headers['Pragma'] = 'no-cache'

    return headers
