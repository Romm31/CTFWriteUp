import hmac
import hashlib

key = b"koenci"
auth_value = b"user:admin|bank:Fortis Bank"

sig = hmac.new(key, auth_value, hashlib.sha256).hexdigest()
print("auth=" + auth_value.decode())
print("sig=" + sig)
