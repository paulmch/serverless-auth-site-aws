"""OAuth2 `state` handling shared by the decider and the callback.

The decider mints a random nonce, stores it in a short-lived HttpOnly cookie and
sends `<nonce>:<redirect path>` as the OAuth `state`. The callback requires the
nonce coming back from Cognito to match the cookie before it will exchange the
authorization code.

That check is what makes the flow resistant to login CSRF: without it, an
attacker can feed a victim's browser a callback URL carrying the attacker's own
authorization code and silently sign the victim into the attacker's account.
The cookie is SameSite=Lax, which still reaches the callback because Cognito
returns the user via a top-level GET navigation.

The redirect path rides along in the same value so the user lands back where
they were, rather than always at the site root.
"""

import hmac
import secrets
from typing import Tuple

# Name of the cookie holding the state nonce, and how long it stays valid. The
# window only needs to cover one trip through the Cognito hosted UI.
OAUTH_STATE_COOKIE = 'oauth_state'
OAUTH_STATE_MAX_AGE = 600  # 10 minutes

# Cap on the stored redirect path, to keep the state parameter a sane size.
_MAX_REDIRECT_LENGTH = 512


def safe_redirect_path(candidate: str, default: str = '/') -> str:
    """Return `candidate` if it is a safe same-origin path, else `default`.

    Only site-relative paths are allowed. Anything that could send the browser
    to another origin is rejected, which keeps this endpoint from being used as
    an open redirect:

    - absolute URLs (`https://evil.example`)
    - protocol-relative URLs (`//evil.example`)
    - backslash variants that some browsers normalise to `//` (`/\\evil.example`)
    - control characters that could truncate the Location header
    """
    if not candidate or not isinstance(candidate, str):
        return default

    if len(candidate) > _MAX_REDIRECT_LENGTH:
        return default

    # Reject anything with characters that could break out of the header.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in candidate):
        return default

    # Must be site-relative...
    if not candidate.startswith('/'):
        return default

    # ...and not scheme-relative, in either slash direction.
    if candidate.startswith('//') or candidate.startswith('/\\'):
        return default

    return candidate


def build_state(redirect_to: str) -> Tuple[str, str]:
    """Create a `(nonce, state)` pair for a login redirect."""
    nonce = secrets.token_urlsafe(32)
    return nonce, f"{nonce}:{safe_redirect_path(redirect_to)}"


def parse_state(state: str, expected_nonce: str) -> Tuple[bool, str]:
    """Validate a returned `state` against the nonce from the cookie.

    Returns `(is_valid, redirect_path)`. The redirect path is only meaningful
    when `is_valid` is True.
    """
    if not state or not expected_nonce:
        return False, '/'

    nonce, separator, redirect_to = state.partition(':')
    if not separator:
        return False, '/'

    # Constant-time compare - this is an authentication check.
    if not hmac.compare_digest(nonce, expected_nonce):
        return False, '/'

    return True, safe_redirect_path(redirect_to)
