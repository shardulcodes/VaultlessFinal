import os, string
from app import generate_password, DEVICE_SECRET  # import from your app
import itertools

# Expanded test parameters
names = [
    "shardul.shekatkar@cisogenie.com/outlook","alice", "bob", "charlie", "dave", "eve", "mallory", "trent", "peggy",
    "", "123", "!@#", "longusernameexample", "user_with_underscores",
    "CAPSLOCK", "mixedCASE123", "😊emoji", "空白", "أحمد"
]

master_passwords = [
    "Shardul@1612","pass123", "helloWorld", "P@$$w0rd", "", "123456", "longpasswordexample",
    "Complex!@#Password", "CAPS123", "mixedCase123", "😊emojiPass", "空白密码"
]

lengths = list(range(16, 17))  # 8 to 32

# Track failures
failures = []

total_tests = len(names) * len(master_passwords) * len(lengths)
current_test = 0

print(f" Starting password length validation for {total_tests} test cases...\n")

for name, mp, length in itertools.product(names, master_passwords, lengths):
    current_test += 1
    pwd = generate_password(name, mp, length, DEVICE_SECRET)
    
    # Verbose progress
    print(
        f"[{current_test}/{total_tests}] "
        f"Name: {name!r}, Master: {mp!r}, Length: {length} -> "
        f"Generated: {pwd!r} (Length: {len(pwd) if pwd else 'None'})"
    )
    
    if not pwd or len(pwd) != length:
        failures.append((name, mp, length, pwd))

print("\n==================== Test Summary ====================")
if failures:
    print(f"Failures detected: {len(failures)}")
    for f in failures:
        print(f"Name: {f[0]!r}, Master: {f[1]!r}, Length: {f[2]}, Result: {f[3]!r}")
else:
    print("All tests passed! Password lengths are correct for all inputs.")
print("======================================================")
