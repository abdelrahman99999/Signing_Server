from fastapi import FastAPI
from pydantic import BaseModel
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime, timedelta
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

app = FastAPI()

@app.get("/")
async def index():
    return {"message": "Hello World! welcome to our Server"}


def cert_chain_generate(root_id,binary_data):
    if(root_id == '1'):
        with open('private_root_key1.pem', 'rb') as f:
            ca_key_data = f.read()
    elif(root_id == '2'):
        with open('private_root_key2.pem', 'rb') as f:
            ca_key_data = f.read()
    
    ca_key = load_pem_private_key(ca_key_data, password=None)
    # Create a self-signed CA certificate
    ca_builder = x509.CertificateBuilder()
    ca_builder = ca_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'My CA'),
    ]))
    ca_builder = ca_builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'My CA'),
    ]))
    ca_builder = ca_builder.not_valid_before(datetime.utcnow())
    ca_builder = ca_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    ca_builder = ca_builder.serial_number(x509.random_serial_number())
    ca_builder = ca_builder.public_key(ca_key.public_key())
    ca_builder = ca_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    ca_builder = ca_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False,
    )
    ca_builder = ca_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
        ), critical=False,
    )

    ca_cert = ca_builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )
    Root_der_cert = ca_cert.public_bytes(serialization.Encoding.DER)

    # Generate a CSR for a new certificate
    SB_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    #################################
    pem = SB_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    key = RSA.import_key(pem)
    h = SHA256.new(binary_data)

    signer=pkcs1_15.new(key)
    signature_bin=signer.sign(h)
    #################################
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'My Common Name'),
    ]))
    csr_builder = csr_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    csr = csr_builder.sign(
        private_key=SB_key,
        algorithm=hashes.SHA256(),
    )
    # Sign the CSR with the CA certificate to create a new certificate
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(csr.subject)
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    cert_builder = cert_builder.not_valid_before(datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.public_key(csr.public_key())
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    cert = cert_builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )
    SB_der_cert = cert.public_bytes(serialization.Encoding.DER)
    return Root_der_cert,SB_der_cert,signature_bin

class file_(BaseModel):
    name: str
    content: bytes
@app.post("/uploadfile/")
async def create_upload_file(metaDataFile: file_):
    binary_data = base64.b64decode(metaDataFile.content)
    root_index = chr(binary_data[0x26])
    Root_der_cert,SB_der_cert,signature_bin = cert_chain_generate(root_index,binary_data)
    signature_base64 = base64.b64encode(signature_bin).decode('utf-8')
    Root_der_cert_base64 =base64.b64encode(Root_der_cert).decode('utf-8')
    SB_der_cert_base64 =base64.b64encode(SB_der_cert).decode('utf-8')
    return {"ROOT_DER_CERT": Root_der_cert_base64,"SB_DER_CERT": SB_der_cert_base64,"SIGNATURE":signature_base64}


