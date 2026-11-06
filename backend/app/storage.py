import boto3
from botocore.exceptions import ClientError
from .config import settings

def client():
    return boto3.client("s3", endpoint_url=settings.s3_endpoint, aws_access_key_id=settings.s3_access_key, aws_secret_access_key=settings.s3_secret_key, region_name=settings.s3_region)
def ensure_bucket():
    s3 = client()
    try: s3.head_bucket(Bucket=settings.s3_bucket)
    except ClientError: s3.create_bucket(Bucket=settings.s3_bucket)
    try: s3.delete_bucket_policy(Bucket=settings.s3_bucket)
    except ClientError as exc:
        if exc.response.get("Error",{}).get("Code") not in {"NoSuchBucketPolicy", "NoSuchBucket"}: raise
    s3.put_bucket_cors(Bucket=settings.s3_bucket, CORSConfiguration={"CORSRules":[{"AllowedOrigins":["http://localhost:5173"],"AllowedMethods":["GET","POST","PUT","HEAD"],"AllowedHeaders":["*"],"ExposeHeaders":["ETag"],"MaxAgeSeconds":300}]})
def upload_url(key: str, size: int):
    ensure_bucket()
    signer = boto3.client("s3", endpoint_url=settings.s3_public_endpoint, aws_access_key_id=settings.s3_access_key, aws_secret_access_key=settings.s3_secret_key, region_name=settings.s3_region)
    return signer.generate_presigned_post(Bucket=settings.s3_bucket, Key=key, Fields={"Content-Type":"application/octet-stream"}, Conditions=[{"Content-Type":"application/octet-stream"},["content-length-range",size,size]], ExpiresIn=settings.upload_url_seconds)
def download_url(key: str):
    signer = boto3.client("s3", endpoint_url=settings.s3_public_endpoint, aws_access_key_id=settings.s3_access_key, aws_secret_access_key=settings.s3_secret_key, region_name=settings.s3_region)
    return signer.generate_presigned_url("get_object", Params={"Bucket": settings.s3_bucket, "Key": key}, ExpiresIn=settings.upload_url_seconds)
def object_info(key: str): return client().head_object(Bucket=settings.s3_bucket, Key=key)
