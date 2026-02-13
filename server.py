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
import traceback
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

LINKO_API_BASE = os.getenv("LINKO_API_BASE", "https://www.linko.study")
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
# Global State (In-Memory)
# ---------------------------------------------------------------------------
# In a real production app, use Redis or a database.
AUTH_CODES: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Linko OAuth Provider Implementation (for Claude)
# ---------------------------------------------------------------------------

class LinkoOAuthProvider(OAuthProvider):
    """
    Custom OAuth provider that bridges MCP's OAuth flow to Linko's auth system.
    Authentication is handled via the /login endpoints defined below.
    """
    
    def __init__(self, base_url: str):
        super().__init__(base_url=base_url)
        # Pre-register a default client for users who want fixed credentials
        self.add_client(
            client_id="linko",
            client_secret="linko",
            redirect_uri="https://chatgpt.com"
        )
        
    async def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        # 1. Try to find registered client
        client = self._clients.get(client_id)
        if client:
            return client
            
        # 2. Fallback: Allow any client_id (treat as public client / skip secret check)
        return {
            "client_id": client_id,
            "redirect_uris": [],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }

    async def authorize(self, request: Request) -> Any:
        # Redirect to explicit login page
        login_url = f"{SERVER_URL}/login"
        # login_url = f"https://www.linko.study/login"
        
        # Pass through all query parameters (including code_challenge)
        if request.query_params:
            import urllib.parse
            login_url += "?" + urllib.parse.urlencode(dict(request.query_params))
            
        return RedirectResponse(login_url)

    async def exchange_token(self, request: Request) -> Dict[str, Any]:
        # This is called by FastMCP when it receives the code
        form = await request.form()
        code = form.get("code")
        
        data = AUTH_CODES.get(code)
        if not data or data["expires_at"] < datetime.now().timestamp():
            raise ValueError("Invalid or expired authorization code")
            
        # Burn the code (one-time use)
        if code in AUTH_CODES:
            del AUTH_CODES[code]
        
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

app = FastAPI(
    title="Linko Hybrid Server",
    version="1.0",
    servers=[{"url": SERVER_URL}]
)

# ---------------------------------------------------------------------------
# Explicit Auth Routes (Custom Login Page)
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Renders the login page for Authenticating with Linko."""
    params = request.query_params
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "")
    
    html = f"""
    <html>
    <head>
        <title>Login to Linko MCP</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f9fafb; margin: 0; }}
            .card {{ background: white; padding: 2rem; rounded: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); width: 100%; max-width: 320px; text-align: center; border-radius: 8px; }}
            input {{ display: block; width: 100%; padding: 0.75rem; margin: 0.5rem 0; border: 1px solid #d1d5db; border-radius: 4px; box-sizing: border-box; font-size: 16px; }}
            button {{ background: #2563eb; color: white; border: none; padding: 0.75rem; width: 100%; border-radius: 4px; font-weight: bold; cursor: pointer; margin-top: 1rem; font-size: 16px; }}
            button:hover {{ background: #1d4ed8; }}
            h2 {{ color: #111827; margin-bottom: 1.5rem; }}
            .error {{ color: #dc2626; margin-bottom: 1rem; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Linko Sign In</h2>
            <form method="POST">
                <input type="hidden" name="client_id" value="{client_id}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="state" value="{state}">
                <input type="hidden" name="code_challenge" value="{code_challenge}">
                <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
                
                <input type="email" name="username" placeholder="Email (Linko Account)" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign In</button>
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.post("/login")
async def login_submit(request: Request):
    """Handles login submission, verifies with Linko API, and redirects."""
    try:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        redirect_uri = form.get("redirect_uri")
        state = form.get("state")
        code_challenge = form.get("code_challenge")
        
        # 1. Verify credentials with Linko
        resp = http_requests.post(
            LINKO_LOGIN_URL,
            json={"email": username, "password": password},
            timeout=10
        )
        
        if resp.status_code != 200:
            logger.warning(f"Login failed: {resp.status_code} {resp.text}")
            return HTMLResponse(f"<h3>Login failed</h3><p>Invalid credentials or server error.</p><a href='/login?redirect_uri={redirect_uri}&state={state}'>Try again</a>", status_code=401)
            
        data = resp.json()
        linko_token = data.get("access")
        if not linko_token:
            return HTMLResponse("<h3>Error</h3><p>No token received from Linko.</p>", status_code=500)

        # 2. Generate Auth Code
        code = secrets.token_urlsafe(32)
        AUTH_CODES[code] = {
            "linko_token": linko_token,
            "expires_at": datetime.now().timestamp() + 300,  # 5 minutes
            "code_challenge": code_challenge
        }
        
        # 3. Redirect back to Custom GPT / Claude
        target = f"{redirect_uri}?code={code}&state={state}"
        logger.info(f"Login success. Redirecting to: {target}")
        return RedirectResponse(target, status_code=302)
        
    except Exception as e:
        logger.error(f"Login error: {traceback.format_exc()}")
        return HTMLResponse(f"<h3>Server Error</h3><p>{str(e)}</p>", status_code=500)

# Marketplace: Privacy Policy (Required for Public Actions)
@app.get("/privacy", response_class=HTMLResponse)
async def privacy_policy():
    return """
    <html>
        <head><title>Linko AI Privacy Policy</title></head>
        <body style="font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 20px;">
            <h1>Privacy Policy</h1>
            <p>The Linko AI Action accesses your Linko account only to search notes and resources upon your specific request.</p>
            <p><strong>Data Usage:</strong> Your search queries and the returned notes/resources are processed transiently to provide the AI response. No personal data is stored on this intermediate server.</p>
            <p><strong>Third Party:</strong> This service bridges ChatGPT/Claude to the Linko API (linko.study).</p>
            <p><strong>Contact:</strong> For questions, please contact the developer.</p>
        </body>
    </html>
    """

# Marketplace: Domain Verification (Optional stub if OpenAI requires file upload)
# If OpenAI gives you a code "openai-verify-token-123", return it here.
@app.get("/.well-known/openai-domain-verification")
async def openai_verification():
    return "verify-token-from-openai"

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
    request: Request,
    body: SearchNotesRequest,
):
    """Search Linko notes (ChatGPT Action)."""
    # Extract token manually to avoid exposing it in OpenAPI schema
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
         raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    
    token = auth_header.removeprefix("Bearer ").strip()
    client = _get_api_client(token)
    try:
        notes = client.get_notes_sync(keyword=body.keyword, limit=body.limit, subject_name=body.subject_name)
        return {"results": notes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chatgpt/get_resources", operation_id="getResources")
async def chatgpt_get_resources(
    request: Request,
    body: GetResourcesRequest,
):
    """Search Linko resources (ChatGPT Action)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
         raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")

    token = auth_header.removeprefix("Bearer ").strip()
    client = _get_api_client(token)
    try:
        resources = client.get_resources_sync(keyword=body.keyword, limit=body.limit)
        return {"results": resources}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

