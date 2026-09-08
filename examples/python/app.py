"""Representative Python SDK integration; SuperTokens Core owns all auth state."""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supertokens_python import InputAppInfo, SupertokensConfig, get_all_cors_headers, init
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.ingredients.emaildelivery.types import EmailDeliveryConfig, EmailDeliveryInterface
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword import EmailPasswordOverrideConfig
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.fastapi import verify_session

CORE_URL = os.environ.get("SUPERTOKENS_CONNECTION_URI", "http://core-a:3567").rstrip("/")
CORE_API_KEY = os.environ.get("SUPERTOKENS_API_KEY", os.environ.get("EXPERTAUTH_CORE_API_KEY", ""))
API_DOMAIN = os.environ.get("PYTHON_API_DOMAIN", "http://localhost:8300")
WEBSITE_DOMAIN = os.environ.get("WEBSITE_DOMAIN", "http://localhost:8300")
if not CORE_API_KEY or len(CORE_API_KEY) < 20:
    raise RuntimeError("Configure a nonempty Core API key of at least 20 characters")
if urlparse(CORE_URL).scheme not in {"http", "https"} or not urlparse(CORE_URL).hostname:
    raise RuntimeError("Core connection URI must identify the private HTTP service")


class DisabledEmailDelivery(EmailDeliveryInterface):
    async def send_email(self, template_vars: Any, user_context: dict[str, Any]) -> None:
        raise RuntimeError("Email delivery is unavailable until a local transport is configured")


def disable_reset_apis(original):
    original.disable_generate_password_reset_token_post = True
    original.disable_password_reset_post = True
    return original


init(
    app_info=InputAppInfo(app_name="ExpertAuth Python", api_domain=API_DOMAIN, website_domain=WEBSITE_DOMAIN, api_base_path="/auth", website_base_path="/auth"),
    supertokens_config=SupertokensConfig(connection_uri=CORE_URL, api_key=CORE_API_KEY),
    framework="fastapi",
    mode="asgi",
    telemetry=False,
    recipe_list=[
        emailpassword.init(
            override=EmailPasswordOverrideConfig(apis=disable_reset_apis),
            email_delivery=EmailDeliveryConfig(service=DisabledEmailDelivery()),
        ),
        session.init(cookie_same_site="lax", cookie_secure=urlparse(API_DOMAIN).scheme == "https", anti_csrf="VIA_CUSTOM_HEADER"),
    ],
)

app = FastAPI(title="ExpertAuth Python representative client", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(get_middleware())
app.add_middleware(CORSMiddleware, allow_origins=[WEBSITE_DOMAIN], allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], allow_headers=["Content-Type", *get_all_cors_headers()])


@app.get("/live")
async def live():
    return {"status": "alive"}


@app.get("/ready")
async def ready():
    # Readiness demonstrates Core connectivity; it is separate from process liveness.
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            response = await client.get(CORE_URL + "/apiversion", headers={"api-key": CORE_API_KEY})
            response.raise_for_status()
            if "5.4" not in response.json().get("versions", []):
                raise ValueError("The pinned Python SDK requires CDI 5.4")
    except (httpx.HTTPError, ValueError):
        raise HTTPException(status_code=503, detail="Identity service unavailable or incompatible") from None
    return {"status": "ready", "sdk": "supertokens-python@0.31.3", "cdi_required": "5.4", "password_reset": "blocked-local-transport-not-configured"}


@app.get("/protected")
async def protected(verified: SessionContainer = Depends(verify_session(check_database=True))):
    return {"userId": verified.get_user_id(), "tenantId": verified.get_tenant_id(), "verification": "signature-and-online-session-check"}


@app.post("/protected/action")
async def protected_action(verified: SessionContainer = Depends(verify_session(check_database=True))):
    return {"userId": verified.get_user_id(), "accepted": True}
