import os, string, itertools, base64
from app import generate_password  # ensure app.py is importable

# ==================== Supabase hex-encoded secret key ====================
SUPABASE_SECRET_KEY_HEX = r"\x7544685962522b4d6746796b6469626734456b722f574e5247594948784738794b3464314a77595164365573766570754e72796a675a476b744233713451433256647a306a5370764b784942524e546266466e6844513d3d"

# Decode like in your app
def decode_secret_key(key_str: str) -> bytes:
    if key_str.startswith(r"\x"):
        # hex decoding
        return bytes.fromhex(key_str[2:])
    else:
        # fallback base64 decoding
        return base64.b64decode(key_str)

USER_SECRET_KEY = decode_secret_key(SUPABASE_SECRET_KEY_HEX)

# ==================== Test Parameters ====================
names = [
    "alice", "bob", "charlie", "dave", "eve", "mallory", "trent", "peggy",
    "", "123", "!@#", "longusernameexample", "user_with_underscores",
    "CAPSLOCK", "mixedCASE123", "😊emoji", "空白", "أحمد"
]

master_passwords = [
    "pass123", "helloWorld", "P@$$w0rd", "", "123456", "longpasswordexample",
    "Complex!@#Password", "CAPS123", "mixedCase123", "😊emojiPass", "空白密码"
]

lengths = list(range(8, 33))  # 8 to 32

# ==================== Track Failures ====================
failures = []

total_tests = len(names) * len(master_passwords) * len(lengths)
current_test = 0

print(f"Starting password length validation for {total_tests} test cases...\n")

# ==================== Test Loop ====================
for name, mp, length in itertools.product(names, master_passwords, lengths):
    current_test += 1
    pwd = generate_password(name, mp, length, USER_SECRET_KEY)
    
    # Verbose progress
    print(f"[{current_test}/{total_tests}] Name: {name!r}, Master: {mp!r}, Length: {length} -> Generated Length: {len(pwd) if pwd else 'None'}")
    
    if not pwd or len(pwd) != length:
        failures.append((name, mp, length, pwd))

# ==================== Test Summary ====================
print("\n==================== Test Summary ====================")
if failures:
    print(f"Failures detected: {len(failures)}")
    for f in failures:
        print(f"Name: {f[0]!r}, Master: {f[1]!r}, Length: {f[2]}, Result: {f[3]!r}")
else:
    print("All tests passed! Password lengths are correct for all inputs.")
print("======================================================")
