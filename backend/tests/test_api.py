import hashlib
import os
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app
from app import storage, chain

engine = create_engine("sqlite://", connect_args={"check_same_thread":False},poolclass=StaticPool)
TestingSession=sessionmaker(bind=engine,expire_on_commit=False)
Base.metadata.create_all(engine)
def override_db():
    db=TestingSession()
    try: yield db
    finally: db.close()
app.dependency_overrides[get_db]=override_db
client=TestClient(app)
@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(engine);Base.metadata.create_all(engine)
    yield
def account(email):
    r=client.post('/api/v1/auth/register',json={'email':email,'password':'correct horse battery staple'})
    assert r.status_code==201
    return r.json()['access_token']
def headers(token): return {'Authorization':f'Bearer {token}'}
def test_registration_login_and_cross_user_isolation(monkeypatch):
    owner=account('owner@example.com'); stranger=account('stranger@example.net')
    monkeypatch.setattr(storage,'upload_url',lambda key,size:{'url':'https://storage.invalid/upload','fields':{}})
    body={'filename':'secret.txt','mime_type':'text/plain','size':33,'digest':'a'*64}
    created=client.post('/api/v1/files',json=body,headers=headers(owner)); assert created.status_code==201
    fid=created.json()['file_id']; vid=created.json()['version_id']
    assert client.get('/api/v1/files',headers=headers(stranger)).json()['items']==[]
    assert client.post(f'/api/v1/files/{fid}/versions/{vid}/download-url',headers=headers(stranger)).status_code==404
    assert client.post(f'/api/v1/files/{fid}/versions/{vid}/integrity/report',json={'outcome':'digest_mismatch'},headers=headers(stranger)).status_code==404
    assert client.post(f'/api/v1/files/{fid}/versions/{vid}/integrity/report',json={'outcome':'digest_mismatch'},headers=headers(owner)).status_code==202
    login=client.post('/api/v1/auth/login',json={'email':'owner@example.com','password':'correct horse battery staple'})
    assert login.status_code==200 and login.json()['crypto_backup'] is None
    assert client.post('/api/v1/auth/logout',headers=headers(owner)).status_code==200
    assert client.get('/api/v1/auth/me',headers=headers(owner)).status_code==401
def test_complete_requires_uploaded_ciphertext_match(monkeypatch):
    token=account('owner2@example.com');monkeypatch.setattr(storage,'upload_url',lambda key,size:{'url':'https://storage.invalid/upload','fields':{}})
    raw=b'SCFS'+bytes([1])+bytes(12)+bytes(16);digest=hashlib.sha256(raw).hexdigest()
    created=client.post('/api/v1/files',json={'filename':'x','mime_type':'application/octet-stream','size':len(raw),'digest':digest},headers=headers(token)).json()
    class Body:
        def read(self,n):return raw[:-1]+b'X'
    monkeypatch.setattr(storage,'client',lambda: type('S3',(),{'get_object':lambda self,**kwargs:{'Body':Body()}})())
    response=client.post(f"/api/v1/files/{created['file_id']}/versions/{created['version_id']}/complete",headers=headers(token))
    assert response.status_code==422 and 'digest' in response.json()['detail']

def test_upload_is_ready_only_after_object_and_chain_match(monkeypatch):
    token=account('owner4@example.com');monkeypatch.setattr(storage,'upload_url',lambda key,size:{'url':'https://storage.invalid/upload','fields':{}})
    raw=b'SCFS'+bytes([1])+bytes(12)+bytes(16);digest=hashlib.sha256(raw).hexdigest()
    created=client.post('/api/v1/files',json={'filename':'demo.bin','size':len(raw),'digest':digest},headers=headers(token)).json()
    class Body:
        def read(self,n):return raw
    monkeypatch.setattr(storage,'client',lambda:type('S3',(),{'get_object':lambda self,**kwargs:{'Body':Body()}})())
    record={}
    def read(file_id,version_id):return (record['digest'],123) if record else None
    def register(file_id,version_id,value):record['digest']=value;return ('0xabc',123)
    monkeypatch.setattr(chain,'read',read);monkeypatch.setattr(chain,'register',register)
    done=client.post(f"/api/v1/files/{created['file_id']}/versions/{created['version_id']}/complete",headers=headers(token))
    assert done.status_code==200 and done.json()['status']=='ready' and done.json()['digest']==digest
    listed=client.get('/api/v1/files',headers=headers(token)).json()['items'][0]
    assert listed['versions'][0]['status']=='ready'

def test_missing_object_remains_non_success(monkeypatch):
    token=account('owner5@example.com');monkeypatch.setattr(storage,'upload_url',lambda key,size:{'url':'https://storage.invalid/upload','fields':{}})
    created=client.post('/api/v1/files',json={'filename':'gone.bin','size':33,'digest':'a'*64},headers=headers(token)).json()
    def missing(self,**kwargs):raise KeyError('object missing')
    monkeypatch.setattr(storage,'client',lambda:type('S3',(),{'get_object':missing})())
    response=client.post(f"/api/v1/files/{created['file_id']}/versions/{created['version_id']}/complete",headers=headers(token))
    assert response.status_code==404

def test_wrapped_file_key_is_owner_scoped_and_immutable(monkeypatch):
    owner=account('key-owner@example.com');other=account('key-other@example.com');monkeypatch.setattr(storage,'upload_url',lambda key,size:{'url':'https://storage.invalid/upload','fields':{}})
    created=client.post('/api/v1/files',json={'filename':'keyed.bin','size':33,'digest':'b'*64},headers=headers(owner)).json()
    path=f"/api/v1/files/{created['file_id']}/versions/{created['version_id']}/key-backup"
    payload={'nonce':'ab'*12,'wrapped_dek':'cd'*48}
    assert client.put(path,json=payload,headers=headers(owner)).status_code==200
    assert client.get(path,headers=headers(owner)).json()==payload
    assert client.get(path,headers=headers(other)).status_code==404
    assert client.put(path,json={'nonce':'ef'*12,'wrapped_dek':'cd'*48},headers=headers(owner)).status_code==409
def test_integrity_fails_closed_when_chain_entry_is_missing(monkeypatch):
    token=account('owner3@example.com');monkeypatch.setattr(storage,'upload_url',lambda key,size:{'url':'https://storage.invalid/upload','fields':{}})
    c=client.post('/api/v1/files',json={'filename':'x','size':33,'digest':'a'*64},headers=headers(token)).json()
    monkeypatch.setattr(chain,'read',lambda *_:None)
    result=client.get(f"/api/v1/files/{c['file_id']}/versions/{c['version_id']}/integrity",headers=headers(token))
    assert result.status_code==404
