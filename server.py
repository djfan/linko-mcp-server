"""
Linko MCP Server — Hybrid Architecture (MCP + OpenAPI)

Supports:
1. Claude Desktop/Web via MCP Protocol (SSE + OAuth 2.1)
2. ChatGPT via OpenAPI Actions (REST + Bearer Token)
"""

import os
import logging
from typing import Optional, Dict, Any, List
import secrets
from datetime import datetime, timedelta

import requests as http_requests
from fastmcp import FastMCP, Context
from fastmcp.server.auth import OAuthProvider
from fastmcp.exceptions import ToolError
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LINKO_API_BASE = os.getenv("LINKO_API_BASE", "https://api.linko.study")
LINKO_LOGIN_URL = f"{LINKO_API_BASE}/api/auth/login/"
LINKO_ME_URL = f"{LINKO_API_BASE}/v1/me"

# Public URL of this MCP server (injected by Railway or set manually)
SERVER_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN")
if SERVER_URL:
    if not SERVER_URL.startswith("http"):
        SERVER_URL = f"https://{SERVER_URL}"
else:
    SERVER_URL = "http://localhost:8000"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("linko-mcp-server")


# ---------------------------------------------------------------------------
# Linko OAuth Provider Implementation (for Claude)
# ---------------------------------------------------------------------------

class LinkoOAuthProvider(OAuthProvider):
    """
    Custom OAuth provider that bridges MCP's OAuth flow to Linko's auth system.
    """
    
    def __init__(self, base_url: str):
        super().__init__(base_url=base_url)
        self._auth_codes: Dict[str, Dict[str, Any]] = {}
        self._clients: Dict[str, Dict[str, Any]] = {}

    async def authorize(self, request: Request) -> Any:
        params = request.query_params
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        state = params.get("state")
        
        # Auto-register unknown clients (for demo/dev simplicity)
        if client_id and client_id not in self._clients:
            logger.info(f"Auto-registering unknown client: {client_id}")
            self._clients[client_id] = {
                "client_id": client_id,
                "redirect_uris": [redirect_uri] if redirect_uri else []
            }

        if request.method == "GET":
            return self._render_login_form(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state
            )
            
        if request.method == "POST":
            return await self._process_login(request)

    def _render_login_form(self, **kwargs) -> HTMLResponse:
        html = f"""
        <html>
        <head>
            <title>Login to Linko</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f9fafb; margin: 0; }}
                .card {{ background: white; padding: 2rem; rounded: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); width: 100%; max-width: 320px; text-align: center; border-radius: 8px; }}
                input {{ display: block; width: 100%; padding: 0.75rem; margin: 0.5rem 0; border: 1px solid #d1d5db; border-radius: 4px; box-sizing: border-box; font-size: 16px; }}
                button {{ background: #2563eb; color: white; border: none; padding: 0.75rem; width: 100%; border-radius: 4px; font-weight: bold; cursor: pointer; margin-top: 1rem; font-size: 16px; }}
                button:hover {{ background: #1d4ed8; }}
                h2 {{ color: #111827; margin-bottom: 1.5rem; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Connect Linko</h2>
                <form method="POST">
                    <input type="hidden" name="client_id" value="{kwargs.get('client_id', '')}">
                    <input type="hidden" name="redirect_uri" value="{kwargs.get('redirect_uri', '')}">
                    <input type="hidden" name="state" value="{kwargs.get('state', '')}">
                    
                    <input type="email" name="username" placeholder="Email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Sign In</button>
                </form>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(html)

    async def _process_login(self, request: Request) -> Any:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        
        try:
            resp = http_requests.post(
                LINKO_LOGIN_URL,
                json={"email": username, "password": password},
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json()
            linko_token = data.get("access")
            
            if not linko_token:
                return HTMLResponse("Login failed: Linko API returned no token", status_code=401)
                
        except Exception as e:
            logger.error(f"Linko login failed: {e}")
            return HTMLResponse(f"Login failed: Invalid credentials or API error", status_code=401)

        code = secrets.token_urlsafe(32)
        redirect_uri = form.get("redirect_uri")
        state = form.get("state")
        
        self._auth_codes[code] = {
            "linko_token": linko_token,
            "expires_at": datetime.now().timestamp() + 300
        }
        
        target = f"{redirect_uri}?code={code}&state={state}"
        return RedirectResponse(target, status_code=302)

    async def exchange_token(self, request: Request) -> Dict[str, Any]:
        form = await request.form()
        code = form.get("code")
        
        data = self._auth_codes.get(code)
        if not data or data["expires_at"] < datetime.now().timestamp():
            raise ValueError("Invalid or expired authorization code")
            
        del self._auth_codes[code]
        
        return {
            "access_token": data["linko_token"],
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "api:read"
        }

    async def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            resp = http_requests.get(
                LINKO_ME_URL,
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "active": True,
                    "sub": str(data.get("id", "unknown")),
                    "scope": "api:read"
                }
        except Exception:
            pass
        return {"active": False}
        
    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        return self._clients.get(client_id)

    def register_client(self, client_metadata: Dict[str, Any]) -> Dict[str, Any]:
        client_id = secrets.token_urlsafe(16)
        return self._clients.setdefault(client_id, {
            "client_id": client_id,
            "client_secret": secrets.token_urlsafe(32),
            **client_metadata
        })


# ---------------------------------------------------------------------------
# Setup FastMCP (for Claude)
# ---------------------------------------------------------------------------

auth_provider = LinkoOAuthProvider(base_url=f"{SERVER_URL}/mcp")
mcp = FastMCP("Linko", auth=auth_provider)

# Check for linko-mcp package
try:
    from linko_mcp.api_client import LinkoAPIClient  # type: ignore[import]
    _HAS_LINKO = True
except ImportError:
    _HAS_LINKO = False
    logger.warning("linko_mcp package not found — tools will return stub responses.")


def _get_api_client(token: str) -> "LinkoAPIClient":
    if not _HAS_LINKO:
        raise ToolError("linko_mcp package is not installed")
    return LinkoAPIClient(access_token=token)


# ---------------------------------------------------------------------------
# Define Tools (Shared Logic)
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_notes(
    ctx: Context,
    keyword: Optional[str] = None,
    limit: int = 10,
    subject_name: Optional[str] = None,
) -> str:
    """Search your Linko notes."""
    if not _HAS_LINKO: return "[stub] search_notes"
    
    # Extract token from Context (populated by OAuth or manual header)
    token = _extract_token_from_ctx(ctx)
    client = _get_api_client(token)
    
    try:
        notes = client.get_notes_sync(keyword=keyword, limit=limit, subject_name=subject_name)
        if not notes: return "No notes found."
        return "\n\n".join(f"**{n.get('title')}**\n{n.get('content','')[:200]}..." for n in notes)
    except Exception as e:
        raise ToolError(f"Error: {e}")

@mcp.tool()
async def get_resources(ctx: Context, keyword: Optional[str] = None, limit: int = 10) -> str:
    """Search Linko resources."""
    if not _HAS_LINKO: return "[stub] get_resources"

    token = _extract_token_from_ctx(ctx)
    client = _get_api_client(token)
    
    try:
        resources = client.get_resources_sync(keyword=keyword, limit=limit)
        if not resources: return "No resources found."
        return "\n\n".join(f"**{r.get('title')}**\n{r.get('description','')[:200]}..." for r in resources)
    except Exception as e:
        raise ToolError(f"Error: {e}")
        
def _extract_token_from_ctx(ctx: Context) -> str:
    """Helper to get token from MCP context (works for both OAuth and manual header)."""
    # 1. Try OAuth token (if FastMCP populated it)
    if ctx.auth and ctx.auth.token:
        return ctx.auth.token.access_token # Adjust based on exact FastMCP internals
        
    # 2. Fallback to raw Authorization header
    try:
        auth = ctx.request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.removeprefix("Bearer ").strip()
    except:
        pass
        
    raise ToolError("Unauthorized: Missing valid token")


# ---------------------------------------------------------------------------
# Setup FastAPI (for ChatGPT)
# ---------------------------------------------------------------------------

app = FastAPI(title="Linko Hybrid Server", version="1.0")

# Mount MCP endpoints (sse, messages, authorize, etc.) at /mcp
# This handles all Claude traffic automatically
app.mount("/mcp", mcp.http_app())

# ChatGPT Request Models
class SearchNotesRequest(BaseModel):
    keyword: Optional[str] = None
    limit: int = 10
    subject_name: Optional[str] = None

class GetResourcesRequest(BaseModel):
    keyword: Optional[str] = None
    limit: int = 10

# ChatGPT Endpoints
@app.post("/chatgpt/search_notes", operation_id="searchNotes")
async def chatgpt_search_notes(
    body: SearchNotesRequest,
    authorization: str = Header(..., description="Bearer <token>")
):
    """Search Linko notes (ChatGPT Action)."""
    token = authorization.removeprefix("Bearer ").strip()
    client = _get_api_client(token)
    try:
        notes = client.get_notes_sync(keyword=body.keyword, limit=body.limit, subject_name=body.subject_name)
        return {"results": notes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chatgpt/get_resources", operation_id="getResources")
async def chatgpt_get_resources(
    body: GetResourcesRequest,
    authorization: str = Header(..., description="Bearer <token>")
):
    """Search Linko resources (ChatGPT Action)."""
    token = authorization.removeprefix("Bearer ").strip()
    client = _get_api_client(token)
    try:
        resources = client.get_resources_sync(keyword=body.keyword, limit=body.limit)
        return {"results": resources}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

