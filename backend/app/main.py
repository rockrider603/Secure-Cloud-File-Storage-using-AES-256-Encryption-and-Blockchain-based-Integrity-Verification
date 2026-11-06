import hashlib
import re
from uuid import uuid4
from pathlib import PurePath
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from jose import jwt
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import select, func
from .db import Base, engine, get_db
from .models import User, File, FileVersion, WrappedFileKey, AccessSession, utcnow
from .security import current_user, hash_password, verify_password, make_token, oauth
from . import storage, chain
from .audit import record
from .audit import request_correlation_id
from .rate_limit import auth_limiter

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Secure Cloud File Storage API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=False, allow_methods=["GET","POST","DELETE","OPTIONS"], allow_headers=["Authorization","Content-Type"])
MAX_FILE_BYTES = 100 * 1024 * 1024

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
class CryptoBackup(BaseModel):
    salt: str = Field(min_length=32, max_length=128)
    nonce: str = Field(min_length=24, max_length=64)
    wrapped_key: str = Field(min_length=44, max_length=256)
    iterations: int = Field(ge=600000, le=2000000)
class NewFile(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(default="application/octet-stream", max_length=255)
    size: int = Field(ge=1, le=MAX_FILE_BYTES + 33)
    digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
class NewVersion(NewFile): pass
class IntegrityReport(BaseModel):
    outcome: Literal["digest_mismatch", "object_missing", "decrypt_failed"]
class WrappedKeyEnvelope(BaseModel):
    nonce: str = Field(pattern=r"^[a-fA-F0-9]{24}$")
    wrapped_dek: str = Field(pattern=r"^[a-fA-F0-9]{96}$")

@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    supplied=request.headers.get("X-Request-ID","")
    correlation=supplied if len(supplied)<=64 and re.fullmatch(r"[A-Za-z0-9_-]+",supplied) else str(uuid4())
    context=request_correlation_id.set(correlation)
    try:
        response=await call_next(request); response.headers["X-Request-ID"]=correlation; return response
    finally: request_correlation_id.reset(context)

def own_file(db, user, file_id):
    file = db.execute(select(File).options(joinedload(File.versions)).where(File.id == file_id, File.owner_id == user.id, File.archived.is_(False))).unique().scalar_one_or_none()
    if not file:
        record(db,user.id,"file_access",None,"denied");db.commit();raise HTTPException(404, "File not found")
    return file
def serialize_file(file):
    versions = sorted(file.versions, key=lambda x: x.version_number, reverse=True)
    return {"id": file.id, "filename": file.filename, "mime_type": file.mime_type, "created_at": file.created_at.isoformat(), "versions": [{"id":v.id,"version_number":v.version_number,"size":v.size,"digest":v.digest,"status":v.status,"created_at":v.created_at.isoformat(),"tx_hash":v.tx_hash} for v in versions]}
def create_pending(db, file_id, number, size, digest):
    version_id, key = str(uuid4()), uuid4().hex + uuid4().hex
    version = FileVersion(id=version_id, file_id=file_id, version_number=number, object_key=key, size=size, digest=digest.lower(), status="pending")
    db.add(version); db.commit(); db.refresh(version)
    try: upload = storage.upload_url(key,size)
    except Exception as exc: raise HTTPException(503, "Private object storage is unavailable") from exc
    return version, upload

@app.get("/health")
def health(): return {"status":"ok"}

@app.post("/api/v1/auth/register", status_code=201)
def register(body: Credentials, request: Request, db: Session = Depends(get_db)):
    remote=auth_limiter.check(request)
    email = str(body.email).strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        auth_limiter.fail(remote); raise HTTPException(409, "An account with this email already exists")
    user = User(id=str(uuid4()), email=email, password_hash=hash_password(body.password))
    db.add(user); record(db,user.id,"register",None,"success"); db.commit()
    token=make_token(user,db); db.commit(); auth_limiter.clear(remote)
    return {"access_token":token,"token_type":"bearer","user":{"id":user.id,"email":user.email}}

@app.post("/api/v1/auth/login")
def login(body: Credentials, request: Request, db: Session = Depends(get_db)):
    remote=auth_limiter.check(request)
    user = db.scalar(select(User).where(User.email == str(body.email).strip().lower()))
    if not user or not verify_password(body.password, user.password_hash):
        auth_limiter.fail(remote); record(db, user.id if user else None,"login",None,"denied"); db.commit(); raise HTTPException(401,"Email or password is incorrect")
    record(db,user.id,"login",None,"success"); db.commit()
    token=make_token(user,db); db.commit(); auth_limiter.clear(remote)
    return {"access_token":token,"token_type":"bearer","user":{"id":user.id,"email":user.email},"crypto_backup":({"salt":user.crypto_salt.hex(),"nonce":user.wrapping_nonce.hex(),"wrapped_key":user.wrapped_key.hex(),"iterations":user.kdf_iterations} if user.crypto_salt else None)}

@app.post("/api/v1/auth/logout")
def logout(token: str = Depends(oauth), user: User = Depends(current_user), db: Session = Depends(get_db)):
    claims=jwt.get_unverified_claims(token); session=db.get(AccessSession,claims.get("jti"))
    if session: session.revoked_at=utcnow()
    record(db,user.id,"logout",None,"success"); db.commit(); return {"status":"signed_out"}

@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user)):
    return {"id":user.id,"email":user.email,"crypto_backup":({"salt":user.crypto_salt.hex(),"nonce":user.wrapping_nonce.hex(),"wrapped_key":user.wrapped_key.hex(),"iterations":user.kdf_iterations} if user.crypto_salt else None)}

@app.put("/api/v1/auth/crypto-backup")
def save_crypto_backup(body: CryptoBackup, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try: salt, nonce, wrapped = bytes.fromhex(body.salt), bytes.fromhex(body.nonce), bytes.fromhex(body.wrapped_key)
    except ValueError: raise HTTPException(422,"Malformed encrypted key backup")
    if len(salt)<16 or len(nonce)!=12 or len(wrapped)!=48: raise HTTPException(422,"Malformed encrypted key backup")
    if user.crypto_salt:
        if user.crypto_salt==salt and user.wrapping_nonce==nonce and user.wrapped_key==wrapped and user.kdf_iterations==body.iterations: return {"status":"already_saved"}
        raise HTTPException(409,"Key backup is immutable; key rotation is not supported in this release")
    user.crypto_salt, user.wrapping_nonce, user.wrapped_key, user.kdf_iterations = salt, nonce, wrapped, body.iterations
    db.commit(); return {"status":"saved"}

@app.get("/api/v1/files")
def list_files(user: User = Depends(current_user), db: Session = Depends(get_db)):
    files = db.execute(select(File).options(joinedload(File.versions)).where(File.owner_id==user.id,File.archived.is_(False)).order_by(File.created_at.desc())).unique().scalars().all()
    return {"items":[serialize_file(f) for f in files]}

@app.get("/api/v1/files/{file_id}")
def get_file(file_id: str,user: User=Depends(current_user),db: Session=Depends(get_db)):
    return serialize_file(own_file(db,user,file_id))

@app.post("/api/v1/files", status_code=201)
def create_file(body: NewFile, user: User = Depends(current_user), db: Session = Depends(get_db)):
    filename = PurePath(body.filename.replace("\\","/")).name.strip()
    if not filename: raise HTTPException(422,"Invalid filename")
    file_id = str(uuid4())
    file = File(id=file_id,owner_id=user.id,filename=filename,mime_type=body.mime_type[:255])
    db.add(file); db.commit()
    version, upload = create_pending(db,file_id,1,body.size,body.digest.lower())
    record(db,user.id,"upload_started",version.id,"pending"); db.commit()
    return {"file_id":file_id,"version_id":version.id,"upload":upload,"expires_in":300}

@app.post("/api/v1/files/{file_id}/versions", status_code=201)
def create_version(file_id: str, body: NewVersion, user: User = Depends(current_user), db: Session = Depends(get_db)):
    file = own_file(db,user,file_id)
    number = max((v.version_number for v in file.versions),default=0)+1
    file.filename=PurePath(body.filename.replace("\\","/")).name.strip() or file.filename; file.mime_type=body.mime_type[:255]
    version,upload=create_pending(db,file.id,number,body.size,body.digest.lower())
    record(db,user.id,"upload_started",version.id,"pending"); db.commit()
    return {"file_id":file.id,"version_id":version.id,"upload":upload,"expires_in":300}

@app.post("/api/v1/files/{file_id}/versions/{version_id}/complete")
def complete(file_id: str, version_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    file=own_file(db,user,file_id)
    version=db.scalar(select(FileVersion).where(FileVersion.id==version_id,FileVersion.file_id==file.id))
    if not version: raise HTTPException(404,"Version not found")
    if version.status=="ready": return {"status":"ready","tx_hash":version.tx_hash}
    try:
        obj=storage.client().get_object(Bucket=storage.settings.s3_bucket,Key=version.object_key)
        data=obj["Body"].read(MAX_FILE_BYTES+34)
        if len(data)>MAX_FILE_BYTES+33: raise HTTPException(413,"Encrypted file exceeds the supported size limit")
        if len(data)!=version.size:
            record(db,user.id,"upload_complete",version.id,"size_mismatch");db.commit();raise HTTPException(422,"Uploaded ciphertext size does not match")
        digest=hashlib.sha256(data).hexdigest()
        if digest!=version.digest:
            record(db,user.id,"upload_complete",version.id,"digest_mismatch");db.commit();raise HTTPException(422,"Uploaded ciphertext digest does not match")
    except HTTPException: raise
    except Exception as exc:
        record(db,user.id,"upload_complete",version.id,"storage_missing"); db.commit(); raise HTTPException(404,"Uploaded encrypted object is missing") from exc
    try:
        existing=chain.read(file.id,version.id)
        if existing and existing[0].removeprefix("0x").lower()!=digest: raise HTTPException(409,"Conflicting integrity record exists")
        tx_hash,block=chain.register(file.id,version.id,digest) if not existing else (None,None)
        anchored=chain.read(file.id,version.id)
        if not anchored or anchored[0].removeprefix("0x").lower()!=digest: raise HTTPException(503,"Integrity registration could not be confirmed")
        version.tx_hash=tx_hash or version.tx_hash; version.block_number=block or version.block_number; version.status="ready"
        record(db,user.id,"upload_complete",version.id,"success"); db.commit()
        return {"status":"ready","tx_hash":version.tx_hash,"block_number":version.block_number,"digest":digest}
    except HTTPException: raise
    except Exception as exc:
        record(db,user.id,"upload_complete",version.id,"chain_unavailable"); db.commit(); raise HTTPException(503,"Integrity registry is unavailable; upload remains pending") from exc

@app.post("/api/v1/files/{file_id}/versions/{version_id}/download-url")
def get_download(file_id: str,version_id: str,user: User=Depends(current_user),db: Session=Depends(get_db)):
    file=own_file(db,user,file_id)
    version=db.scalar(select(FileVersion).where(FileVersion.id==version_id,FileVersion.file_id==file.id,FileVersion.status=="ready"))
    if not version: raise HTTPException(404,"Ready version not found")
    try: url=storage.download_url(version.object_key)
    except Exception as exc:
        record(db,user.id,"download_url",version.id,"storage_unavailable");db.commit();raise HTTPException(503,"Private object storage is unavailable") from exc
    return {"download_url":url,"filename":file.filename,"mime_type":file.mime_type,"size":version.size,"file_id":file.id,"version_id":version.id,"chain_id":chain.settings.chain_id,"contract_address":chain.settings.chain_contract_address}

@app.put("/api/v1/files/{file_id}/versions/{version_id}/key-backup")
def save_wrapped_key(file_id: str,version_id: str,body: WrappedKeyEnvelope,user: User=Depends(current_user),db: Session=Depends(get_db)):
    file=own_file(db,user,file_id); version=db.scalar(select(FileVersion).where(FileVersion.id==version_id,FileVersion.file_id==file.id))
    if not version: raise HTTPException(404,"Version not found")
    nonce,wrapped=bytes.fromhex(body.nonce),bytes.fromhex(body.wrapped_dek)
    existing=db.get(WrappedFileKey,version.id)
    if existing:
        if existing.owner_id!=user.id or existing.wrapping_nonce!=nonce or existing.wrapped_dek!=wrapped: raise HTTPException(409,"Wrapped version key is immutable")
        return {"status":"already_saved"}
    db.add(WrappedFileKey(version_id=version.id,owner_id=user.id,wrapping_nonce=nonce,wrapped_dek=wrapped));db.commit()
    return {"status":"saved"}

@app.get("/api/v1/files/{file_id}/versions/{version_id}/key-backup")
def get_wrapped_key(file_id: str,version_id: str,user: User=Depends(current_user),db: Session=Depends(get_db)):
    file=own_file(db,user,file_id); version=db.scalar(select(FileVersion).where(FileVersion.id==version_id,FileVersion.file_id==file.id))
    if not version: raise HTTPException(404,"Version not found")
    backup=db.get(WrappedFileKey,version.id)
    if not backup or backup.owner_id!=user.id: raise HTTPException(404,"Encrypted version key backup is missing")
    return {"nonce":backup.wrapping_nonce.hex(),"wrapped_dek":backup.wrapped_dek.hex()}

@app.get("/api/v1/files/{file_id}/versions/{version_id}/integrity")
def integrity(file_id: str,version_id: str,user: User=Depends(current_user),db: Session=Depends(get_db)):
    file=own_file(db,user,file_id); version=db.scalar(select(FileVersion).where(FileVersion.id==version_id,FileVersion.file_id==file.id))
    if not version: raise HTTPException(404,"Version not found")
    try: record_on_chain=chain.read(file.id,version.id)
    except Exception as exc:
        record(db,user.id,"integrity_check",version.id,"chain_unavailable");db.commit();raise HTTPException(503,"Integrity registry is unavailable") from exc
    if not record_on_chain: record(db,user.id,"integrity_check",version.id,"missing_chain_record"); db.commit(); raise HTTPException(404,"Blockchain integrity record is missing")
    return {"digest":record_on_chain[0].removeprefix("0x").lower(),"timestamp":record_on_chain[1],"chain_id":chain.settings.chain_id,"contract_address":chain.settings.chain_contract_address}

@app.post("/api/v1/files/{file_id}/versions/{version_id}/integrity/report", status_code=202)
def report_integrity(file_id: str,version_id: str,body: IntegrityReport,user: User=Depends(current_user),db: Session=Depends(get_db)):
    file=own_file(db,user,file_id); version=db.scalar(select(FileVersion).where(FileVersion.id==version_id,FileVersion.file_id==file.id))
    if not version: raise HTTPException(404,"Version not found")
    record(db,user.id,"download_verification",version.id,body.outcome); db.commit()
    return {"status":"recorded"}

@app.delete("/api/v1/files/{file_id}")
def archive(file_id: str,user: User=Depends(current_user),db: Session=Depends(get_db)):
    file=own_file(db,user,file_id); file.archived=True; record(db,user.id,"file_archive",file.id,"success"); db.commit(); return {"status":"archived","chain_records_retained":True}

@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    return JSONResponse(status_code=500,content={"detail":"Internal service error"})
