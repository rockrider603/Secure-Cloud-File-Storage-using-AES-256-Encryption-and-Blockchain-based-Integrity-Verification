from datetime import datetime, timedelta, timezone
from uuid import uuid4
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import settings
from .db import get_db
from .models import User, AccessSession, utcnow

pwd = CryptContext(schemes=["argon2"], deprecated="auto")
oauth = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
def hash_password(value: str): return pwd.hash(value)
def verify_password(value: str, encoded: str): return pwd.verify(value, encoded)
def make_token(user: User, db: Session):
    now = datetime.now(timezone.utc)
    jti = str(uuid4()); expires = now + timedelta(minutes=settings.access_token_minutes)
    db.add(AccessSession(jti=jti,user_id=user.id,expires_at=expires))
    return jwt.encode({"sub": user.id, "iss": settings.jwt_issuer, "iat": now, "exp": expires, "jti": jti}, settings.jwt_secret, algorithm="HS256")
def current_user(token: str = Depends(oauth), db: Session = Depends(get_db)):
    try: payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], issuer=settings.jwt_issuer)
    except JWTError: raise HTTPException(401, "Invalid or expired access token")
    session = db.get(AccessSession, payload.get("jti"))
    user = db.get(User, payload.get("sub"))
    if not user or not session or session.user_id != user.id or session.revoked_at: raise HTTPException(401, "Session is invalid or signed out")
    return user
