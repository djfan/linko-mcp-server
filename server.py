"""
Linko MCP Server — Deployable wrapper for the linko-mcp package.

Hosts the Linko MCP tools over SSE with Bearer Token authentication
that validates users against the Linko backend before allowing tool use.
"""

import os
import logging
from typing import Optional

import requests as http_requests
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LINKO_API_BASE = os.getenv("LINKO_API_BASE", "https://api.linko.study")
VERIFY_ENDPOINT = f"{LINKO_API_BASE}/v1/me"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("linko-mcp-server")

# ---------------------------------------------------------------------------
# FastMCP initialization
# ---------------------------------------------------------------------------

mcp = FastMCP("Linko")

# ---------------------------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------------------------


async def verify_user(ctx: Context) -> str:
    """Extract the Bearer token from the request and validate it against
    the Linko backend.  Returns the authenticated ``user_id`` on success,
    or raises ``ToolError("Unauthorized")`` on failure.
    """

    # Retrieve the Authorization header from the transport / session metadata.
    # FastMCP injects request headers into the context when running over SSE.
    auth_header: Optional[str] = None

    # Try extracting from the request headers attached to the context
    try:
        request = ctx.request
        if request and hasattr(request, "headers"):
            auth_header = request.headers.get("Authorization")
    except Exception:
        pass

    # Fallback: check if the token was passed as a session parameter
    if not auth_header:
        try:
            session = ctx.session
            if session and hasattr(session, "headers"):
                auth_header = session.headers.get("Authorization")
        except Exception:
            pass

    if not auth_header or not auth_header.startswith("Bearer "):
        raise ToolError(
            "Unauthorized — missing or malformed Authorization header. "
            "Expected: 'Bearer <token>'"
        )

    token = auth_header.removeprefix("Bearer ").strip()

    # Validate the token against the Linko upstream API
    try:
        resp = http_requests.get(
            VERIFY_ENDPOINT,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
    except http_requests.RequestException as exc:
        logger.error("Failed to reach Linko API for token verification: %s", exc)
        raise ToolError("Unauthorized — unable to verify token with Linko API")

    if resp.status_code == 200:
        data = resp.json()
        user_id = str(data.get("id", data.get("user_id", "unknown")))
        logger.info("Authenticated user: %s", user_id)
        return user_id

    logger.warning(
        "Token verification failed: HTTP %s — %s",
        resp.status_code,
        resp.text[:200],
    )
    raise ToolError("Unauthorized — invalid or expired token")


# ---------------------------------------------------------------------------
# Tool wrappers  (delegate to the linko_mcp package)
# ---------------------------------------------------------------------------

# The linko-mcp package ships two servers:
#   • mcp-server-linko        → get_notes, get_resources, get_subjects
#   • mcp-server-linko-for-ai → get_notes_for_AI, create_note_for_AI, …
#
# We wrap the human-facing tools here.  If linko_mcp is not installed yet
# (e.g. during local development without the package), the tools still
# register but return a helpful error.

try:
    from linko_mcp.api_client import LinkoAPIClient  # type: ignore[import]

    _HAS_LINKO = True
except ImportError:
    _HAS_LINKO = False
    logger.warning(
        "linko_mcp package not found — tools will return stub responses. "
        "Install it with: pip install linko-mcp"
    )


def _get_client(token: str) -> "LinkoAPIClient":
    """Create a short-lived API client authenticated with the user's token."""
    if not _HAS_LINKO:
        raise ToolError("linko_mcp package is not installed on this server")
    client = LinkoAPIClient(access_token=token)
    return client


@mcp.tool()
async def search_notes(
    ctx: Context,
    keyword: Optional[str] = None,
    limit: int = 10,
    subject_name: Optional[str] = None,
) -> str:
    """Search or list the user's study notes on Linko.

    Args:
        keyword: Optional search term to filter notes.
        limit: Maximum number of notes to return (default 10).
        subject_name: Optional subject name to filter by.
    """
    user_id = await verify_user(ctx)

    if not _HAS_LINKO:
        return (
            f"[stub] search_notes called for user {user_id} "
            f"with keyword={keyword!r}, limit={limit}"
        )

    auth_header = ctx.request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    client = _get_client(token)

    try:
        notes = client.get_notes_sync(
            keyword=keyword, limit=limit, subject_name=subject_name
        )
        if not notes:
            return "No notes found matching your query."
        return "\n\n".join(
            f"**{n.get('title', 'Untitled')}**\n{n.get('content', '')[:300]}"
            for n in notes
        )
    except Exception as exc:
        logger.error("search_notes error: %s", exc)
        raise ToolError(f"Failed to search notes: {exc}")


@mcp.tool()
async def get_resources(
    ctx: Context,
    keyword: Optional[str] = None,
    limit: int = 10,
) -> str:
    """Search learning resources (books, papers, articles) on Linko.

    Args:
        keyword: Optional search term to filter resources.
        limit: Maximum number of resources to return (default 10).
    """
    user_id = await verify_user(ctx)

    if not _HAS_LINKO:
        return (
            f"[stub] get_resources called for user {user_id} "
            f"with keyword={keyword!r}, limit={limit}"
        )

    auth_header = ctx.request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    client = _get_client(token)

    try:
        resources = client.get_resources_sync(keyword=keyword, limit=limit)
        if not resources:
            return "No resources found matching your query."
        return "\n\n".join(
            f"**{r.get('title', 'Untitled')}** ({r.get('type', 'unknown')})\n"
            f"{r.get('description', '')[:300]}"
            for r in resources
        )
    except Exception as exc:
        logger.error("get_resources error: %s", exc)
        raise ToolError(f"Failed to get resources: {exc}")


@mcp.tool()
async def get_subjects(ctx: Context) -> str:
    """Get the user's knowledge distribution across subjects on Linko."""
    user_id = await verify_user(ctx)

    if not _HAS_LINKO:
        return f"[stub] get_subjects called for user {user_id}"

    auth_header = ctx.request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    client = _get_client(token)

    try:
        subjects = client.get_subjects_sync()
        if not subjects:
            return "No subjects found."
        return "\n".join(
            f"• {s.get('name', 'Unknown')} — {s.get('note_count', 0)} notes"
            for s in subjects
        )
    except Exception as exc:
        logger.error("get_subjects error: %s", exc)
        raise ToolError(f"Failed to get subjects: {exc}")


# ---------------------------------------------------------------------------
# ASGI app  (served by uvicorn)
# ---------------------------------------------------------------------------

app = mcp.get_asgi_app()
