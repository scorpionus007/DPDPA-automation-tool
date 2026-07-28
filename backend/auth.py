import os
from datetime import datetime, timedelta
from typing import Optional, Tuple
import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.database import get_db
from fastapi import Request

_load_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_load_env)

# Config Variables
SECRET_KEY = os.environ.get("SECRET_KEY", "your_fallback_secret_key_which_is_insecure")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))


def verify_password(plain_password, hashed_password):
    """Check if the provided plain password matches the hashed password."""
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password_bytes)


def get_password_hash(password):
    """Generate a bcrypt hashed representation of the password."""
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password=pwd_bytes, salt=salt).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new signed JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)



async def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.split(" ")[1]
    else:
        token = request.query_params.get("token")
        
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not token:
        raise credentials_exception
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    from backend.models import User
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


def _require_role(membership, min_roles: set[str]) -> None:
    if membership.role not in min_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient organization permissions",
        )


async def get_current_org(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    x_org_id: Optional[int] = Header(None, alias="X-Org-Id"),
) -> Tuple:
    """
    Resolve active organization from X-Org-Id header and validate membership.
    Returns (organization, membership).
    """
    from backend.models import Organization, OrgMembership

    org_id = x_org_id
    if org_id is None:
        org_id = request.query_params.get("org_id")
        if org_id is not None:
            try:
                org_id = int(org_id)
            except ValueError:
                org_id = None
    if org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Org-Id header is required",
        )
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    membership = (
        db.query(OrgMembership)
        .filter(
            OrgMembership.org_id == org_id,
            OrgMembership.user_id == current_user.id,
        )
        .first()
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this organization",
        )
    return org, membership


async def get_current_org_admin(
    org_membership=Depends(get_current_org),
) -> Tuple:
    org, membership = org_membership
    _require_role(membership, {"owner", "admin"})
    return org, membership
