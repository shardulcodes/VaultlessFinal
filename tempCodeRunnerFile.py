def generate_password(name: str, master_password: str, length: int, key: bytes = None) -> str:
    if length < 8 or length > 64:
        return None
    secret = key or DEVICE_SECRET
    combined = secret + f"{name}{master_password}{length}".encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=secret, iterations=100000)
    derived_key = kdf.derive(combined)
    hash_digest = hmac.new(derived_key, combined, hashlib.sha256).hexdigest()
    charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(charset[int(hash_digest[i * 2:(i * 2) + 2], 16) % len(charset)] for i in range(length))