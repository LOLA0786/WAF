import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import hashlib

class UserRole(Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class User(BaseModel):
    user_id: str
    email: str
    role: UserRole
    api_limits: Dict[str, int]
    is_active: bool = True

class APIToken(BaseModel):
    token: str
    user_id: str
    expires_at: datetime
    scopes: List[str]

class EnterpriseAuthManager:
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.security = HTTPBearer()
        self.users = {}
        self.tokens = {}
        
        # Initialize with admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user"""
        admin_user = User(
            user_id="admin_001",
            email="admin@company.com",
            role=UserRole.SUPER_ADMIN,
            api_limits={"scans_per_hour": 1000, "optimizations_per_day": 500}
        )
        self.users[admin_user.user_id] = admin_user
    
    def create_user(self, email: str, role: UserRole = UserRole.VIEWER) -> User:
        """Create new user"""
        user_id = hashlib.sha256(f"{email}{datetime.now()}".encode()).hexdigest()[:16]
        
        # Set API limits based on role
        api_limits = {
            "scans_per_hour": 100 if role == UserRole.VIEWER else 500,
            "optimizations_per_day": 50 if role == UserRole.VIEWER else 200
        }
        
        user = User(
            user_id=user_id,
            email=email,
            role=role,
            api_limits=api_limits
        )
        
        self.users[user_id] = user
        return user
    
    def generate_api_token(self, user_id: str, scopes: List[str] = None) -> APIToken:
        """Generate JWT API token"""
        if user_id not in self.users:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = self.users[user_id]
        expires_at = datetime.now() + timedelta(days=30)
        
        payload = {
            "user_id": user_id,
            "email": user.email,
            "role": user.role.value,
            "scopes": scopes or ["read", "write"],
            "exp": expires_at
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        api_token = APIToken(token=token, user_id=user_id, expires_at=expires_at, scopes=scopes or [])
        
        self.tokens[token] = api_token
        return api_token
    
    def verify_token(self, token: str) -> User:
        """Verify JWT token and return user"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            user_id = payload.get("user_id")
            
            if user_id not in self.users:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            user = self.users[user_id]
            if not user.is_active:
                raise HTTPException(status_code=401, detail="User account disabled")
            
            return user
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def check_permission(self, user: User, required_role: UserRole, required_scope: str = None) -> bool:
        """Check if user has required permissions"""
        role_hierarchy = {
            UserRole.VIEWER: 1,
            UserRole.EDITOR: 2,
            UserRole.ADMIN: 3,
            UserRole.SUPER_ADMIN: 4
        }
        
        if role_hierarchy[user.role] < role_hierarchy[required_role]:
            return False
        
        if required_scope and required_scope not in getattr(user, 'scopes', []):
            return False
        
        return True
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> User:
        """Dependency to get current user from token"""
        return self.verify_token(credentials.credentials)

class RateLimiter:
    def __init__(self):
        self.requests = {}
    
    def is_rate_limited(self, user_id: str, endpoint: str, limits: Dict[str, int]) -> bool:
        """Check if user has exceeded rate limits"""
        current_time = datetime.now()
        key = f"{user_id}:{endpoint}"
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Clean old requests (older than 1 hour)
        self.requests[key] = [
            req_time for req_time in self.requests[key] 
            if current_time - req_time < timedelta(hours=1)
        ]
        
        # Check limits
        hourly_limit = limits.get("scans_per_hour", 100)
        if len(self.requests[key]) >= hourly_limit:
            return True
        
        self.requests[key].append(current_time)
        return False

# Global instances
auth_manager = EnterpriseAuthManager()
rate_limiter = RateLimiter()

# Dependency for admin access
def require_admin(user: User = Depends(auth_manager.get_current_user)):
    if not auth_manager.check_permission(user, UserRole.ADMIN):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Dependency for editor access
def require_editor(user: User = Depends(auth_manager.get_current_user)):
    if not auth_manager.check_permission(user, UserRole.EDITOR):
        raise HTTPException(status_code=403, detail="Editor access required")
    return user
