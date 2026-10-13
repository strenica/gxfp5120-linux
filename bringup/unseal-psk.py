#!/usr/bin/env python3
"""unseal-psk.py — extract the fingerprint sensor's 32-byte PSK from the DPAPI-sealed
Goodix_Cache.bin on the (read-only mounted) Windows partition.

YOU run this; your Windows password is asked locally and is never stored or printed.

Run:
    uv run --with impacket python unseal-psk.py

Or to just locate the files (no password asked):
    uv run --with impacket python unseal-psk.py --dry-run

Output: ./psk_raw32.bin (32 bytes, chmod 600) + its sha256 so success is verifiable.
"""
import argparse
import getpass
import glob
import hashlib
import hmac
import os
import sys

# --- entropy derivation (same constants as the gxfp5130 unseal tool) ---
CONST_1 = bytes.fromhex("9d7992b38402b66c81d1f555218942a9")
CONST_2 = bytes.fromhex("1848d71550d270d219c80632ab4f8bb3")
CONST_3 = bytes.fromhex("e47c8938db5250f0205617ee17da4eb4")


def derive_root_key() -> bytes:
    out = bytearray(16)
    for i in range(8):
        out[i] = CONST_1[i] ^ CONST_2[i] ^ CONST_1[i + 8]
    for i in range(8, 16):
        out[i] = CONST_2[i] ^ CONST_3[i] ^ CONST_3[i - 8]
    return bytes(out)


def derive_entropy(seed8: bytes) -> bytes:
    seed_hash = hashlib.sha256(seed8).digest()
    session_key = hashlib.sha256(seed_hash[:16] + derive_root_key()).digest()
    return seed_hash[16:] + session_key


def find_cache(explicit=None):
    if explicit:
        return explicit
    pats = [
        "/media/*/*/ProgramData/Goodix/Goodix_Cache.bin",
        "/media/*/*/*/ProgramData/Goodix/Goodix_Cache.bin",
    ]
    found = []
    for p in pats:
        found += glob.glob(p)
    if not found:
        return None
    found.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return found[0]


def blob_masterkey_guid(blob: bytes) -> str:
    d1 = int.from_bytes(blob[24:28], "little")
    d2 = int.from_bytes(blob[28:30], "little")
    d3 = int.from_bytes(blob[30:32], "little")
    d4 = blob[32:40]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:2].hex()}-{d4[2:].hex()}"


def find_masterkey_files(users_glob):
    """All DPAPI user masterkey files on the (mounted) Windows partition."""
    files = {}
    for root in glob.glob(users_glob):
        for sid_dir in glob.glob(os.path.join(root, "*")):
            sid = os.path.basename(sid_dir)
            if not sid.startswith("S-1-5-21"):
                continue
            for f in glob.glob(os.path.join(sid_dir, "*")):
                if os.path.isfile(f) and len(os.path.basename(f)) >= 30:
                    files[os.path.basename(f).lower()] = f
    return files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", help="path to Goodix_Cache.bin (default: auto-find)")
    ap.add_argument("--protect-root", default="/media/*/*/Users/*/AppData/Roaming/Microsoft/Protect",
                    help="glob for the DPAPI Protect folders")
    ap.add_argument("--out", default="psk_raw32.bin")
    ap.add_argument("--dry-run", action="store_true", help="only locate files, do not ask for password")
    args = ap.parse_args()

    cache = find_cache(args.cache)
    if not cache:
        print("ERROR: Goodix_Cache.bin not found. Is the Windows partition mounted? (udisksctl mount -b /dev/nvme0n1p3 -o ro)")
        return 1
    print(f"cache file : {cache}")
    data = open(cache, "rb").read()
    seed8, blob = data[-8:], data[:-8]
    entropy = derive_entropy(seed8)
    print(f"seed8      : {seed8.hex()}")
    print(f"entropy    : {entropy.hex()}")
    print(f"dpapi blob : {len(blob)} bytes")

    guid = blob_masterkey_guid(blob)
    print(f"master key guid: {guid}")

    mkfiles = find_masterkey_files(args.protect_root)
    print(f"masterkey files found on partition: {len(mkfiles)}")
    target = mkfiles.get(guid)
    if target:
        print(f"matching masterkey file: {target}")
    else:
        print("no exact-guid masterkey file found; will try all found files")

    if args.dry_run:
        print("dry run complete — re-run without --dry-run to unseal (will ask for your Windows password)")
        return 0

    from impacket.dpapi import MasterKey, DPAPI_BLOB

    password = getpass.getpass("Windows account password (not stored): ")
    try:
        from Cryptodome.Hash import MD4
        ntlm = MD4.new(password.encode("utf-16-le")).digest()
    except ImportError:
        print("ERROR: Cryptodome missing — run with: uv run --with impacket python unseal-psk.py")
        return 1

    order = ([target] if target else []) + [p for p in mkfiles.values() if p != target]
    if not order:
        print("ERROR: no DPAPI masterkey files found for any user on the partition")
        return 1

    for mkpath in order:
        sid = os.path.basename(os.path.dirname(mkpath))
        sid_b = sid.encode("utf-16-le")
        keys = [
            ntlm,
            hmac.new(ntlm, sid_b, hashlib.sha1).digest(),
            hmac.new(ntlm, sid_b + b"\x00", hashlib.sha1).digest(),
            hmac.new(ntlm, sid_b, hashlib.sha1).digest()[:16],
            hmac.new(ntlm, sid_b + b"\x00", hashlib.sha1).digest()[:16],
        ]
        for key in keys:
            mk = MasterKey(open(mkpath, "rb").read())
            try:
                mk.decrypt(key)
            except Exception:
                continue
            if not mk.decryptedKey:
                continue
            try:
                psk = DPAPI_BLOB(blob).decrypt(mk.decryptedKey, entropy=entropy)
            except Exception:
                continue
            if len(psk) != 32:
                print(f"decrypted but unexpected length ({len(psk)}) — aborting")
                return 1
            with open(args.out, "wb") as f:
                f.write(psk)
            os.chmod(args.out, 0o600)
            h = hashlib.sha256(psk).hexdigest()
            print(f"SUCCESS: wrote {args.out} (32 bytes)  sha256={h}")
            return 0

    print("ERROR: could not unseal the blob. Wrong password, or the cache was sealed under a different Windows account.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
