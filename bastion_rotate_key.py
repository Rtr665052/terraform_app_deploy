import boto3
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def lambda_handler(event, context):
    secrets = boto3.client("secretsmanager")
    private_secret_arn = event.get("PRIVATE_SECRET_ARN") or context.function_name
    public_secret_arn = event.get("PUBLIC_SECRET_ARN")

    # Generate new RSA key pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')

    # Store new keys in Secrets Manager
    secrets.put_secret_value(SecretId=private_secret_arn, SecretString=private_pem)
    secrets.put_secret_value(SecretId=public_secret_arn, SecretString=public_key)

    return {"status": "success", "message": "Rotated SSH key pair"}
