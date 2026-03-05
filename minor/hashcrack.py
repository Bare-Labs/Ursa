#!/usr/bin/env python3
"""
Hash Cracker
============
WHAT THIS DOES:
    Takes a password hash and tries to crack it using:
    1. Dictionary attack (try every word in a wordlist)
    2. Rule-based mutations (add numbers, capitalize, leet speak)
    3. Common password patterns

WHY IT MATTERS:
    When you compromise a database or steal /etc/shadow from a Linux
    box, you get password HASHES, not passwords. You need to crack
    them to get the actual passwords for lateral movement.

    Real operators use Hashcat (GPU-accelerated) and John the Ripper.
    We're building a CPU version to understand the concepts.

HOW HASHING WORKS:
    password → hash function → fixed-length string
    "password123" → MD5 → "482c811da5d5b4bc6d497ffa98491e38"

    You can't reverse a hash. Instead, you hash millions of guesses
    and compare them to the target hash. If they match, you found
    the password.

HASH TYPES:
    MD5:     32 hex chars  (insecure, fast to crack)
    SHA1:    40 hex chars  (insecure, fast)
    SHA256:  64 hex chars  (slow-ish)
    SHA512:  128 hex chars (slower)
    bcrypt:  starts with $2b$ (slow by design — good password storage)

USAGE:
    python3 hashcrack.py <hash>
    python3 hashcrack.py <hash> -w /path/to/wordlist.txt
    python3 hashcrack.py <hash> --rules     # apply mutations
    python3 hashcrack.py -f hashes.txt      # crack multiple hashes
"""

import sys
import hashlib
import argparse
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common passwords — in real engagements you'd use:
# - rockyou.txt (14M passwords from a real breach)
# - SecLists: https://github.com/danielmiessler/SecLists/tree/master/Passwords
DEFAULT_WORDLIST = [
    # Top passwords from breaches
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1",
    "password123", "batman", "login", "welcome", "admin",
    "admin123", "root", "toor", "pass", "changeme",
    "default", "guest", "test", "test123", "temp",
    "temp123", "p@ssw0rd", "P@ssw0rd", "P@ssword1",
    "Summer2024", "Winter2024", "Spring2024", "Fall2024",
    "Summer2025", "Winter2025", "Spring2025", "Fall2025",
    "January2025", "February2025", "March2025",
    "Company1", "Company123", "Welcome1", "Welcome123",
    "Qwerty123", "Password1!", "P@ssw0rd!", "Admin123!",
    "letmein1", "access", "master1", "hello", "charlie",
    "donald", "aa123456", "qwerty123", "password1!",
    "1234567890", "123456789", "000000", "1q2w3e4r",
    "1qaz2wsx", "qwer1234", "zaq1xsw2",
    # Keyboard patterns
    "1q2w3e", "zxcvbnm", "asdfghjkl", "qwertyuiop",
    "1234qwer", "qwer4321", "asdf1234",
    # Simple patterns
    "111111", "222222", "333333", "444444", "555555",
    "666666", "777777", "888888", "999999",
    "aaaaaa", "abcdef", "abcabc",
]


def identify_hash(hash_str):
    """
    Identify hash type by length and format.

    This is the first step — you need to know what algorithm was used
    before you can start cracking.
    """
    hash_str = hash_str.strip()

    # bcrypt
    if hash_str.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"

    # MD5 crypt
    if hash_str.startswith("$1$"):
        return "md5crypt"

    # SHA-256 crypt
    if hash_str.startswith("$5$"):
        return "sha256crypt"

    # SHA-512 crypt
    if hash_str.startswith("$6$"):
        return "sha512crypt"

    # NTLM (Windows)
    if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
        return "md5_or_ntlm"  # Same length, need context

    # By length (raw hashes)
    length = len(hash_str)
    if length == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "md5"
    elif length == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "sha1"
    elif length == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "sha256"
    elif length == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return "sha512"

    return "unknown"


def hash_password(password, hash_type):
    """Hash a password with the specified algorithm."""
    if hash_type in ("md5", "md5_or_ntlm"):
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type == "bcrypt":
        try:
            import bcrypt as bcrypt_lib
            return bcrypt_lib.hashpw(
                password.encode(), hash_str.encode()
            ).decode()
        except ImportError:
            return None
    return None


def apply_rules(word):
    """
    Generate mutations of a word.

    This is how real password crackers work — people don't use
    dictionary words directly. They add numbers, capitalize,
    substitute characters. Rules model these patterns.
    """
    mutations = [word]

    # Capitalize first letter
    mutations.append(word.capitalize())

    # All uppercase
    mutations.append(word.upper())

    # Add common numbers
    for suffix in ["1", "12", "123", "1234", "!", "!!", "1!", "123!",
                   "01", "69", "007", "2024", "2025", "2026",
                   "@1", "#1", "$1"]:
        mutations.append(word + suffix)
        mutations.append(word.capitalize() + suffix)

    # Leet speak substitutions
    leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
    leet = word
    for char, replacement in leet_map.items():
        leet = leet.replace(char, replacement)
    if leet != word:
        mutations.append(leet)

    # Reverse
    mutations.append(word[::-1])

    # Double
    mutations.append(word + word)

    return mutations


def crack_hash(target_hash, wordlist=None, use_rules=False, threads=4):
    """
    Attempt to crack a hash.

    Args:
        target_hash: The hash to crack
        wordlist: List of passwords to try
        use_rules: Apply mutation rules to each word
        threads: Number of threads (limited for CPU-bound work)
    """
    hash_type = identify_hash(target_hash)
    target_hash = target_hash.strip().lower()
    words = wordlist or DEFAULT_WORDLIST

    # Build candidate list
    candidates = []
    for word in words:
        if use_rules:
            candidates.extend(apply_rules(word))
        else:
            candidates.append(word)

    candidates = list(set(candidates))  # Deduplicate
    total = len(candidates)
    start_time = time.time()
    attempts = 0

    for candidate in candidates:
        attempts += 1
        hashed = hash_password(candidate, hash_type)

        if hashed and hashed.lower() == target_hash:
            duration = time.time() - start_time
            rate = attempts / duration if duration > 0 else 0
            return {
                "cracked": True,
                "password": candidate,
                "hash_type": hash_type,
                "attempts": attempts,
                "duration": duration,
                "rate": rate,
            }

        if attempts % 10000 == 0:
            elapsed = time.time() - start_time
            rate = attempts / elapsed if elapsed > 0 else 0
            sys.stdout.write(
                f"\r  [{attempts}/{total}] {rate:.0f} hashes/sec"
            )
            sys.stdout.flush()

    duration = time.time() - start_time
    rate = attempts / duration if duration > 0 else 0

    return {
        "cracked": False,
        "hash_type": hash_type,
        "attempts": attempts,
        "duration": duration,
        "rate": rate,
    }


def main():
    parser = argparse.ArgumentParser(description="Hash Cracker")
    parser.add_argument("hash", nargs="?", help="Hash to crack")
    parser.add_argument("-f", "--file", help="File containing hashes (one per line)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("--rules", action="store_true",
                        help="Apply mutation rules")
    parser.add_argument("--identify", action="store_true",
                        help="Just identify the hash type")

    args = parser.parse_args()

    if not args.hash and not args.file:
        parser.error("Provide a hash or use -f for a file of hashes")

    # Load wordlist
    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [line.strip() for line in f if line.strip()]

    # Collect hashes to crack
    hashes = []
    if args.file:
        with open(args.file) as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        hashes = [args.hash]

    for target in hashes:
        hash_type = identify_hash(target)
        print(f"\n[*] Hash: {target}")
        print(f"[*] Type: {hash_type}")

        if args.identify:
            continue

        if hash_type == "unknown":
            print("[!] Unknown hash type — cannot crack")
            continue

        if hash_type == "bcrypt":
            print("[!] bcrypt is intentionally slow — this will take a while")

        word_count = len(wordlist or DEFAULT_WORDLIST)
        if args.rules:
            word_count *= 15  # Rough estimate with rules
        print(f"[*] Candidates: ~{word_count}")
        print(f"[*] Cracking...\n")

        result = crack_hash(
            target, wordlist=wordlist, use_rules=args.rules,
        )

        if result["cracked"]:
            print(f"\n\n[+] CRACKED!")
            print(f"    Password:  {result['password']}")
            print(f"    Hash type: {result['hash_type']}")
            print(f"    Attempts:  {result['attempts']}")
            print(f"    Time:      {result['duration']:.2f}s")
            print(f"    Rate:      {result['rate']:.0f} hashes/sec")
        else:
            print(f"\n\n[-] Not cracked")
            print(f"    Attempts:  {result['attempts']}")
            print(f"    Time:      {result['duration']:.2f}s")
            print(f"    Rate:      {result['rate']:.0f} hashes/sec")
            print(f"    Try a larger wordlist (rockyou.txt) or enable --rules")


if __name__ == "__main__":
    main()
