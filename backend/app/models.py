from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, LargeBinary, Boolean
from sqlalchemy.orm import mapped_column, relationship
from .db import Base

def utcnow(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__ = "users"
    id = mapped_column(String(36), primary_key=True)
    email = mapped_column(String(320), unique=True, index=True)
    password_hash = mapped_column(String(512))
    created_at = mapped_column(DateTime(timezone=True), default=utcnow)
    crypto_salt = mapped_column(LargeBinary, nullable=True)
    wrapped_key = mapped_column(LargeBinary, nullable=True)
    wrapping_nonce = mapped_column(LargeBinary, nullable=True)
    kdf_iterations = mapped_column(Integer, default=600000)
class AccessSession(Base):
    __tablename__ = "access_sessions"
    jti = mapped_column(String(36), primary_key=True)
    user_id = mapped_column(ForeignKey("users.id"), index=True)
    expires_at = mapped_column(DateTime(timezone=True))
    revoked_at = mapped_column(DateTime(timezone=True), nullable=True)
class File(Base):
    __tablename__ = "files"
    id = mapped_column(String(36), primary_key=True)
    owner_id = mapped_column(ForeignKey("users.id"), index=True)
    filename = mapped_column(String(255))
    mime_type = mapped_column(String(255), default="application/octet-stream")
    created_at = mapped_column(DateTime(timezone=True), default=utcnow)
    archived = mapped_column(Boolean, default=False)
    versions = relationship("FileVersion", back_populates="file", order_by="FileVersion.version_number")
class FileVersion(Base):
    __tablename__ = "file_versions"
    __table_args__ = (UniqueConstraint("file_id", "version_number"), UniqueConstraint("file_id", "id"))
    id = mapped_column(String(36), primary_key=True)
    file_id = mapped_column(ForeignKey("files.id"), index=True)
    version_number = mapped_column(Integer)
    object_key = mapped_column(String(80), unique=True)
    digest = mapped_column(String(64))
    size = mapped_column(Integer)
    status = mapped_column(String(16), default="pending")
    tx_hash = mapped_column(String(80), nullable=True)
    block_number = mapped_column(Integer, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), default=utcnow)
    file = relationship("File", back_populates="versions")
class WrappedFileKey(Base):
    __tablename__ = "wrapped_file_keys"
    version_id = mapped_column(ForeignKey("file_versions.id"), primary_key=True)
    owner_id = mapped_column(ForeignKey("users.id"), index=True)
    wrapping_nonce = mapped_column(LargeBinary)
    wrapped_dek = mapped_column(LargeBinary)
    created_at = mapped_column(DateTime(timezone=True), default=utcnow)
class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = mapped_column(String(36), primary_key=True)
    actor_id = mapped_column(String(36), nullable=True)
    event_type = mapped_column(String(80))
    resource_id = mapped_column(String(36), nullable=True)
    outcome = mapped_column(String(32))
    correlation_id = mapped_column(String(64), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), default=utcnow)
