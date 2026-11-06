from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./securefiles.sqlite3"
    jwt_secret: str = "local-development-secret-change-me"
    jwt_issuer: str = "secure-file-storage-local"
    access_token_minutes: int = 20
    s3_endpoint: str = "http://localhost:9000"
    s3_public_endpoint: str = "http://localhost:9000"
    s3_access_key: str = "dev-minio-user"
    s3_secret_key: str = "dev-minio-secret-change-me"
    s3_bucket: str = "encrypted-files"
    s3_region: str = "us-east-1"
    upload_url_seconds: int = 300
    chain_rpc_url: str = "http://localhost:8545"
    chain_id: int = 31337
    chain_contract_address: str = ""
    chain_private_key: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
