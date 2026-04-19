"""
Aither Shield - SSO Service

Single Sign-On integration with Can I Be ecosystem.
Allows GigBee members to use their existing credentials.
"""

from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import base64
import uuid
import secrets


class SSOProvider(Enum):
    """Supported SSO providers."""
    CANIBE = "canibe"
    GIGBEE = "gigbee"
    GOOGLE = "google"
    APPLE = "apple"
    EMAIL = "email"


class TokenType(Enum):
    """JWT token types."""
    ACCESS = "access"
    REFRESH = "refresh"
    SSO_EXCHANGE = "sso_exchange"


@dataclass
class SSOSession:
    """SSO session data."""
    session_id: str
    user_id: str
    provider: SSOProvider
    provider_user_id: str
    email: str
    name: Optional[str]
    access_token: str
    refresh_token: str
    expires_at: datetime
    scopes: list = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_active_at: datetime = field(default_factory=datetime.now)


@dataclass
class SSOUser:
    """User linked via SSO."""
    id: str
    shield_user_id: Optional[str]
    provider: SSOProvider
    provider_user_id: str
    email: str
    name: Optional[str]
    gigbee_id: Optional[str]
    bee_tier: Optional[str]
    vesting_percent: float = 0.0
    linked_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None


class SSOService:
    """
    Single Sign-On service for Can I Be ecosystem integration.

    Supports:
    - Can I Be ecosystem SSO (GigBee, Hive members)
    - Google OAuth
    - Apple Sign-In
    - Email/password with MFA
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._sessions: Dict[str, SSOSession] = {}
        self._sso_users: Dict[str, SSOUser] = {}
        self._linked_accounts: Dict[str, str] = {}  # provider_user_id -> sso_user_id

        # JWT secrets (in production, use proper key management)
        self._jwt_secret = self.config.get("jwt_secret", secrets.token_hex(32))
        self._sso_exchange_secret = self.config.get("sso_exchange_secret", secrets.token_hex(32))

        # Can I Be API endpoints
        self._canibe_api_base = self.config.get(
            "canibe_api_base",
            "https://api.canibe.io/v1"
        )
        self._gigbee_api_base = self.config.get(
            "gigbee_api_base",
            "https://api.gigbee.io/v1"
        )

    def initiate_sso_login(self, provider: str, redirect_uri: str,
                           state: Optional[str] = None) -> Dict[str, Any]:
        """
        Initiate SSO login flow.

        Returns authorization URL and state parameter.
        """
        provider_enum = SSOProvider(provider)
        state = state or secrets.token_urlsafe(32)

        # Generate authorization URLs based on provider
        auth_urls = {
            SSOProvider.CANIBE: f"{self._canibe_api_base}/oauth/authorize",
            SSOProvider.GIGBEE: f"{self._gigbee_api_base}/oauth/authorize",
            SSOProvider.GOOGLE: "https://accounts.google.com/o/oauth2/v2/auth",
            SSOProvider.APPLE: "https://appleid.apple.com/auth/authorize",
        }

        if provider_enum not in auth_urls:
            return {"success": False, "error": "Unsupported SSO provider"}

        # Build authorization URL
        client_id = self.config.get(f"{provider}_client_id", f"shield_{provider}_client")
        scopes = self._get_provider_scopes(provider_enum)

        auth_url = auth_urls[provider_enum]
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(scopes),
        }

        if provider_enum == SSOProvider.CANIBE:
            params["access_type"] = "offline"
            params["include_gigbee_data"] = "true"

        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        full_url = f"{auth_url}?{query_string}"

        return {
            "success": True,
            "authorization_url": full_url,
            "state": state,
            "provider": provider,
        }

    def complete_sso_login(self, provider: str, authorization_code: str,
                           state: str, redirect_uri: str) -> Dict[str, Any]:
        """
        Complete SSO login after user authorizes.

        Exchanges authorization code for tokens and creates session.
        """
        provider_enum = SSOProvider(provider)

        # In production, exchange code with provider
        # For now, simulate the exchange
        user_data = self._simulate_provider_exchange(provider_enum, authorization_code)

        if not user_data:
            return {"success": False, "error": "Failed to verify authorization"}

        # Find or create SSO user
        sso_user = self._find_or_create_sso_user(provider_enum, user_data)

        # Generate tokens
        access_token = self._generate_access_token(sso_user)
        refresh_token = self._generate_refresh_token(sso_user)

        # Create session
        session = SSOSession(
            session_id=str(uuid.uuid4()),
            user_id=sso_user.id,
            provider=provider_enum,
            provider_user_id=user_data["provider_user_id"],
            email=user_data["email"],
            name=user_data.get("name"),
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.now() + timedelta(hours=24),
            scopes=self._get_provider_scopes(provider_enum),
            metadata=user_data.get("metadata", {}),
        )
        self._sessions[session.session_id] = session
        sso_user.last_login = datetime.now()

        return {
            "success": True,
            "session_id": session.session_id,
            "user": {
                "id": sso_user.id,
                "email": sso_user.email,
                "name": sso_user.name,
                "provider": provider,
                "gigbee_id": sso_user.gigbee_id,
                "bee_tier": sso_user.bee_tier,
                "vesting_percent": sso_user.vesting_percent,
            },
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            },
            "is_new_user": sso_user.shield_user_id is None,
        }

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode an access token."""
        try:
            # In production, use proper JWT verification
            # For now, simulate verification
            parts = token.split(".")
            if len(parts) != 3:
                return {"valid": False, "error": "Invalid token format"}

            # Decode payload
            payload = base64.urlsafe_b64decode(parts[1] + "==")
            claims = eval(payload.decode())  # In production, use json.loads

            # Check expiration
            if datetime.fromtimestamp(claims["exp"]) < datetime.now():
                return {"valid": False, "error": "Token expired"}

            return {
                "valid": True,
                "user_id": claims["sub"],
                "email": claims.get("email"),
                "provider": claims.get("provider"),
                "scopes": claims.get("scopes", []),
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access and refresh tokens."""
        # Find session with this refresh token
        session = None
        for s in self._sessions.values():
            if s.refresh_token == refresh_token:
                session = s
                break

        if not session:
            return {"success": False, "error": "Invalid refresh token"}

        if session.expires_at < datetime.now():
            return {"success": False, "error": "Session expired"}

        # Find SSO user
        sso_user = self._sso_users.get(session.user_id)
        if not sso_user:
            return {"success": False, "error": "User not found"}

        # Generate new tokens
        new_access_token = self._generate_access_token(sso_user)
        new_refresh_token = self._generate_refresh_token(sso_user)

        # Update session
        session.access_token = new_access_token
        session.refresh_token = new_refresh_token
        session.expires_at = datetime.now() + timedelta(hours=24)
        session.last_active_at = datetime.now()

        return {
            "success": True,
            "tokens": {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        }

    def logout(self, session_id: str) -> Dict[str, Any]:
        """Logout and invalidate session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return {"success": True, "message": "Logged out successfully"}
        return {"success": False, "error": "Session not found"}

    def link_shield_account(self, sso_user_id: str, shield_user_id: str) -> Dict[str, Any]:
        """Link SSO user to Shield user account."""
        sso_user = self._sso_users.get(sso_user_id)
        if not sso_user:
            return {"success": False, "error": "SSO user not found"}

        sso_user.shield_user_id = shield_user_id
        return {
            "success": True,
            "sso_user_id": sso_user_id,
            "shield_user_id": shield_user_id,
        }

    def get_gigbee_status(self, sso_user_id: str) -> Dict[str, Any]:
        """Get GigBee membership status for SSO user."""
        sso_user = self._sso_users.get(sso_user_id)
        if not sso_user:
            return {"success": False, "error": "User not found"}

        if not sso_user.gigbee_id:
            return {
                "success": True,
                "is_gigbee_member": False,
                "message": "User is not linked to GigBee account",
            }

        # In production, fetch from GigBee API
        return {
            "success": True,
            "is_gigbee_member": True,
            "gigbee_id": sso_user.gigbee_id,
            "bee_tier": sso_user.bee_tier,
            "vesting_percent": sso_user.vesting_percent,
            "eligible_for_discount": sso_user.vesting_percent >= 0.25,
            "discount_percent": self._calculate_vesting_discount(sso_user.vesting_percent),
        }

    def sync_gigbee_data(self, sso_user_id: str) -> Dict[str, Any]:
        """Sync latest GigBee data for user."""
        sso_user = self._sso_users.get(sso_user_id)
        if not sso_user or not sso_user.gigbee_id:
            return {"success": False, "error": "Not a GigBee member"}

        # In production, fetch from GigBee API
        # Simulate data sync
        import random
        new_vesting = min(1.0, sso_user.vesting_percent + random.uniform(0.01, 0.05))

        sso_user.vesting_percent = new_vesting
        if new_vesting >= 1.0:
            sso_user.bee_tier = "vested"
        elif new_vesting >= 0.75:
            sso_user.bee_tier = "gold"
        elif new_vesting >= 0.50:
            sso_user.bee_tier = "silver"
        elif new_vesting >= 0.25:
            sso_user.bee_tier = "bronze"

        return {
            "success": True,
            "updated": {
                "bee_tier": sso_user.bee_tier,
                "vesting_percent": sso_user.vesting_percent,
                "discount_percent": self._calculate_vesting_discount(sso_user.vesting_percent),
            },
        }

    def _get_provider_scopes(self, provider: SSOProvider) -> list:
        """Get OAuth scopes for provider."""
        scopes = {
            SSOProvider.CANIBE: ["profile", "email", "gigbee:read", "vesting:read"],
            SSOProvider.GIGBEE: ["profile", "email", "wallet:read", "referrals:read"],
            SSOProvider.GOOGLE: ["openid", "profile", "email"],
            SSOProvider.APPLE: ["name", "email"],
            SSOProvider.EMAIL: ["profile", "email"],
        }
        return scopes.get(provider, ["profile", "email"])

    def _simulate_provider_exchange(self, provider: SSOProvider,
                                    code: str) -> Optional[Dict[str, Any]]:
        """Simulate OAuth code exchange (for demo)."""
        # In production, make actual API call
        user_id = hashlib.sha256(code.encode()).hexdigest()[:16]

        base_data = {
            "provider_user_id": f"{provider.value}_{user_id}",
            "email": f"user_{user_id}@{provider.value}.example",
            "name": f"Test User {user_id[:4]}",
        }

        if provider in [SSOProvider.CANIBE, SSOProvider.GIGBEE]:
            base_data["metadata"] = {
                "gigbee_id": f"GB_{user_id}",
                "bee_tier": "silver",
                "vesting_percent": 0.45,
            }

        return base_data

    def _find_or_create_sso_user(self, provider: SSOProvider,
                                  user_data: Dict[str, Any]) -> SSOUser:
        """Find existing or create new SSO user."""
        provider_user_id = user_data["provider_user_id"]
        link_key = f"{provider.value}:{provider_user_id}"

        # Check if already linked
        if link_key in self._linked_accounts:
            sso_user_id = self._linked_accounts[link_key]
            return self._sso_users[sso_user_id]

        # Create new SSO user
        metadata = user_data.get("metadata", {})
        sso_user = SSOUser(
            id=str(uuid.uuid4()),
            shield_user_id=None,
            provider=provider,
            provider_user_id=provider_user_id,
            email=user_data["email"],
            name=user_data.get("name"),
            gigbee_id=metadata.get("gigbee_id"),
            bee_tier=metadata.get("bee_tier"),
            vesting_percent=metadata.get("vesting_percent", 0.0),
        )

        self._sso_users[sso_user.id] = sso_user
        self._linked_accounts[link_key] = sso_user.id

        return sso_user

    def _generate_access_token(self, sso_user: SSOUser) -> str:
        """Generate JWT access token."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": sso_user.id,
            "email": sso_user.email,
            "provider": sso_user.provider.value,
            "exp": int((datetime.now() + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now().timestamp()),
            "scopes": self._get_provider_scopes(sso_user.provider),
        }

        # Simplified JWT (in production use proper library)
        header_b64 = base64.urlsafe_b64encode(str(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(str(payload).encode()).decode().rstrip("=")
        signature = hmac.new(
            self._jwt_secret.encode(),
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256
        ).hexdigest()

        return f"{header_b64}.{payload_b64}.{signature}"

    def _generate_refresh_token(self, sso_user: SSOUser) -> str:
        """Generate refresh token."""
        return secrets.token_urlsafe(48)

    def _calculate_vesting_discount(self, vesting_percent: float) -> float:
        """Calculate discount based on vesting progress."""
        if vesting_percent >= 1.0:
            return 0.20  # 20% off for fully vested
        elif vesting_percent >= 0.75:
            return 0.15  # 15% off
        elif vesting_percent >= 0.50:
            return 0.10  # 10% off
        elif vesting_percent >= 0.25:
            return 0.05  # 5% off
        return 0.0
