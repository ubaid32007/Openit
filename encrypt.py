#!/usr/bin/env python3
"""Usage: python3 encrypt.py "your password"   -> writes index.html (password-protected)
Reads the plain page from habiba-proposal.html (keep that file PRIVATE, never upload it)."""
import sys, os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
if len(sys.argv) < 2: sys.exit('Give a password: python3 encrypt.py "your password"')
pw = sys.argv[1]
plain = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "private","habiba-proposal.html"), "rb").read()
salt, iv = os.urandom(16), os.urandom(12)
ITER = 600000
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, plain, None)
b64 = lambda b: base64.b64encode(b).decode()
page = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "template.html"), encoding="utf-8").read()
page = page.replace("__DATA__", json.dumps({"s": b64(salt), "i": b64(iv), "c": b64(ct), "n": ITER}))
open(os.path.join("upload","index.html"), "w", encoding="utf-8").write(page)
print("index.html written", len(page)//1024, "KB")
