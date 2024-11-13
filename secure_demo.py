import base64
import hmac
import hashlib
import json
import datetime
import random
import string

# Define a secret key for HMAC signing
SECRET_KEY = b'super-secure-key-12345'

# Function to generate a nonce
def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# Encode data to base64 URL-safe format
def urlsafe_b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Decode base64 URL-safe data
def urlsafe_b64decode(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))

# Secure cookie creation with HMAC signing
def create_secure_cookie(user_id, nonce):
    payload = {
        'user_id': user_id,
        'nonce': nonce,
        'exp': (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).isoformat()
    }
    payload_json = json.dumps(payload).encode('utf-8')
    payload_b64 = urlsafe_b64encode(payload_json)

    # HMAC signature
    signature = hmac.new(SECRET_KEY, payload_b64.encode('utf-8'), hashlib.sha256).digest()
    signature_b64 = urlsafe_b64encode(signature)

    # Combine payload and signature to form the token
    token = payload_b64 + '.' + signature_b64
    print("Generated Secure Cookie:", token)
    return token

# Function to validate the secure cookie
def secure_login(token):
    try:
        payload_b64, signature_b64 = token.split('.')
        payload = json.loads(urlsafe_b64decode(payload_b64))

        # Verify expiration time
        exp_time = datetime.datetime.fromisoformat(payload['exp'])
        if datetime.datetime.utcnow() > exp_time:
            print("Token expired. Please log in again.")
            return

        # Recreate HMAC signature
        expected_signature = hmac.new(SECRET_KEY, payload_b64.encode('utf-8'), hashlib.sha256).digest()
        if hmac.compare_digest(urlsafe_b64decode(signature_b64), expected_signature):
            print(f"User {payload['user_id']} authenticated successfully.")
        else:
            print("Invalid token. Authentication failed.")

    except Exception as e:
        print(f"Authentication failed: {e}")

# Main execution
if __name__ == "__main__":
    user_id = "user123"
    nonce = generate_nonce()
    secure_cookie = create_secure_cookie(user_id, nonce)

    # Attempt login with the secure cookie
    print("\nSimulating a secure login attempt:")
    secure_login(secure_cookie)

    # Simulate a tampered token
    print("\nSimulating an attack with a tampered secure cookie:")
    tampered_cookie = secure_cookie + "tampered"
    secure_login(tampered_cookie)