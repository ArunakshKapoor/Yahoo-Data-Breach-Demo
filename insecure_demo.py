import random
import string

# Function to generate a nonce
def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# Insecure cookie creation using nonce without signing
def create_insecure_cookie(user_id, nonce):
    cookie = f"{user_id}:{nonce}"
    print("Generated Insecure Cookie:", cookie)
    return cookie

# Simulate an attacker replaying the cookie
def insecure_login(cookie):
    user_id, nonce = cookie.split(':')
    print(f"Attacker logged in as {user_id} using replayed cookie!")

# Main execution
if __name__ == "__main__":
    user_id = "user123"
    nonce = generate_nonce()
    insecure_cookie = create_insecure_cookie(user_id, nonce)

    # Attacker replays the insecure cookie
    print("\nSimulating an attack with insecure cookie replay:")
    insecure_login(insecure_cookie)
