import hashlib
import requests
import urllib3
import ssl
from Crypto.Cipher import DES


def login():
    # CKV or Semgrep: Hardcoded credential
    admin_password = "supersecretpassword123"
    api_key = "AKIAIOSFODNN7EXAMPLE"  # AWS Access Key

    # CKV or Semgrep: Weak cipher
    h = hashlib.md5(admin_password.encode())
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)

    # CKV or Semgrep: TLS verification disabled
    urllib3.disable_warnings()
    response = requests.get("https://insecure.internal.api", verify=False)

    # SSL create unverified context
    ctx = ssl._create_unverified_context()

    return response.status_code
