#!/usr/bin/env python3
"""analyze-imageread.py — process a cc-imageread run: derive TLS session keys from
the captured handshake, assemble the image frame from the parcel windows, decrypt
the TLS record, decode 12-bit pixels to PNG.

usage: analyze-imageread.py /tmp/ccimg1
"""
import hashlib
import hmac
import re
import struct
import sys
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PFX = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/ccimg1')
PSK = (Path(__file__).resolve().parent.parent / 'psk_raw32.bin').read_bytes()
assert len(PSK) == 32

# ---------- read frames ----------
frames = []  # (t, dir, bytes)
for line in (PFX.parent / (PFX.name + '.frames.txt')).read_text().splitlines():
    parts = line.split()
    if len(parts) >= 4:
        t, kind, n = float(parts[0]), parts[1], int(parts[2])
        try:
            b = bytes.fromhex(parts[3])
        except ValueError:
            continue
        frames.append((t, kind, b))
rx = [f for f in frames if f[1] == 'RX']
print(f'frames: {len(frames)} ({len(rx)} RX)')

def find(pat, seq=None):
    """return frames whose bytes start with hex pat, optionally containing seq hex"""
    out = []
    for t, k, b in frames:
        if b.startswith(bytes.fromhex(pat)) and (seq is None or seq in b.hex()):
            out.append((t, b))
    return out

chs = find('b03400e4')
ckes = find('b01a00ca')
fins = [b for _, _, b in rx if b.startswith(bytes.fromhex('b0550005'))]
print(f'CH={len(chs)} CKE={len(ckes)} sensorFIN={len(fins)}')
if not chs or not ckes or not fins:
    print('!! missing handshake frames — dumping all RX heads:')
    for t, k, b in rx[:40]:
        print(f'  {t:8.3f} {b[:20].hex()}')
    sys.exit(1)
if len({b[15:47] for _, b in chs}) > 1:
    print('!! multiple distinct CH randoms — using last')
ch = chs[-1][1]
client_random = ch[15:47]
cke = ckes[-1][1]
sh = next(b for t, k, b in frames if k == 'TX' and b.startswith(bytes.fromhex('b05600')))
shd = next(b for t, k, b in frames if k == 'TX' and b.startswith(bytes.fromhex('b00900b9')))
CH, SH, SHD, CKE = ch[9:56], sh[9:90], shd[9:13], cke[9:30]
transcript = CH + SH + SHD + CKE
server_random = sh[15:47]
print('client_random:', client_random.hex())
print('transcript len:', len(transcript), '(expect 153)')

def prf(secret, label, seed, n):
    out = b''
    A = hmac.new(secret, label + seed, hashlib.sha256).digest()
    while len(out) < n:
        out += hmac.new(secret, A + label + seed, hashlib.sha256).digest()
        A = hmac.new(secret, A, hashlib.sha256).digest()
    return out[:n]

prem = b'\x00\x20' + b'\0' * 32 + b'\x00\x20' + PSK
master = prf(prem, b'master secret', client_random + server_random, 48)
kb = prf(master, b'key expansion', server_random + client_random, 96)
cmac, smac, cwk, swk = kb[0:32], kb[32:64], kb[64:80], kb[80:96]
th = hashlib.sha256(transcript).digest()
client_vd = prf(master, b'client finished', th, 12)
print('client verify_data:', client_vd.hex())

# validate keys against the sensor's Finished
sfin = fins[-1][9:89]
iv, ct = sfin[:16], sfin[16:]
pt = Cipher(algorithms.AES(cwk), modes.CBC(iv)).decryptor().update(ct)
pad = pt[-1] + 1
content = pt[:-pad]
msg, mac = content[:-32], content[-32:]
h = hmac.new(cmac, (0).to_bytes(8, 'big') + b'\x16\x03\x03' + len(msg).to_bytes(2, 'big') + msg,
             hashlib.sha256).digest()
ok = hmac.compare_digest(h, mac)
print('sensor Finished: HMAC', 'OK' if ok else 'FAIL', '| verify_data',
      'MATCH' if msg == b'\x14\x00\x00\x0c' + client_vd else 'no-match')
if not ok:
    print('!! keys not validated — parcel decrypt will likely fail')

def decrypt_record(rec, seq):
    """rec = full TLS record (17 03 03 len body). returns plaintext or None"""
    if len(rec) < 5 + 16 + 32 or rec[0] != 0x17:
        return None
    blen = (rec[3] << 8) | rec[4]
    if len(rec) < 5 + blen:
        return None
    body = rec[5:5 + blen]
    ivr, ctr = body[:16], body[16:]
    if len(ctr) == 0 or len(ctr) % 16:
        return None
    p = Cipher(algorithms.AES(cwk), modes.CBC(ivr)).decryptor().update(ctr)
    pad = p[-1] + 1
    if not (1 <= pad <= 16) or len(p) < pad + 32:
        return None
    content = p[:-pad]
    msg, mac = content[:-32], content[-32:]
    hh = hmac.new(cmac, seq.to_bytes(8, 'big') + b'\x17\x03\x03' + len(content).to_bytes(2, 'big') + content,
                  hashlib.sha256).digest()
    if hmac.compare_digest(hh, mac):
        return content, seq
    return None

# ---------- read parcels ----------
pb = (PFX.parent / (PFX.name + '.parcels.bin')).read_bytes()
assert len(pb) % 268 == 0, f'parcel file size {len(pb)} not multiple of 268'
npar = len(pb) // 268
wins = []
for i in range(npar):
    off = i * 268
    us, st, win = struct.unpack_from('<Q', pb, off)[0], pb[off+8:off+12], pb[off+12:off+268]
    wins.append((us, st, win))
print(f'parcels: {npar}')

# ---------- locate image frame ----------
# per-parcel heads:
for i, (us, st, w) in enumerate(wins):
    for off in range(0, 8):
        b0 = w[off]
        if b0 in (0xa0, 0xb0, 0xc0) and ((b0 + w[off+1] + w[off+2]) & 0xff) == w[off+3]:
            tot = 4 + w[off+1] + (w[off+2] << 8)
            if tot > 300:
                print(f'  p{i:3d} head@{off}: type={b0:02x} len16={tot-4} csum-ok')
            break

def try_assemble(start_idx, off0=0):
    """assemble from window start_idx at offset off0; returns assembled bytes + expected"""
    first = wins[start_idx][2]
    b0 = first[off0]
    if b0 not in (0xa0, 0xb0, 0xc0):
        return None
    expected = 4 + (first[off0+1] | (first[off0+2] << 8))
    buf = bytearray()
    i = start_idx
    skip = off0
    while len(buf) < expected and i < len(wins):
        w = wins[i][2]
        take = min(256 - skip, expected - len(buf))
        buf += w[skip:skip+take]
        skip = 0
        i += 1
    return bytes(buf[:expected]), expected

found = None
for i, (us, st, w) in enumerate(wins):
    for off in (0, 4, 8):
        b0 = w[off]
        if b0 in (0xa0, 0xb0, 0xc0) and ((b0 + w[off+1] + w[off+2]) & 0xff) == w[off+3]:
            tot = 4 + (w[off+1] | (w[off+2] << 8))
            if tot > 3000:  # big frame = candidate image
                r = try_assemble(i, off)
                if r:
                    buf, exp = r
                    if ((buf[0] + buf[1] + buf[2]) & 0xff) == buf[3] and len(buf) == exp:
                        found = (i, off, buf)
                        print(f'assembled candidate: parcel {i} off {off}, {len(buf)} B (expected {exp})')
                        break
    if found:
        break

if not found:
    print('no clean assembly; dumping window heads of all parcels for manual work:')
    for i, (us, st, w) in enumerate(wins):
        print(f'  p{i:3d} {w[:12].hex()}')
    # fallback: look for TLS record header anywhere in concatenated stream
    allb = b''.join(w for _, _, w in wins)
    pos = allb.find(bytes.fromhex('1703031e40'))
    print('search 17 03 03 1e 40 at stream offset:', pos)
    sys.exit(0)

idx, off, frame = found
print('frame head:', frame[:16].hex())
if frame[0] == 0xb0 and frame[4] == 0x16 and frame[5] == 3:
    rec = frame[4:]
    print(f'TLS record inside: type={rec[0]:02x} ver={rec[1]:02x}{rec[2]:02x} len={rec[3]<<8|rec[4]}')
    out = None
    for seq in range(0, 9):
        r = decrypt_record(rec, seq)
        if r:
            out, s = r
            print(f'*** DECRYPTED with seq={s}, {len(out)} bytes ***')
            break
    if out is None:
        print('!! record decrypt failed for seq 0..8')
        (PFX.parent / (PFX.name + '-record.bin')).write_bytes(rec)
        sys.exit(0)
    (PFX.parent / (PFX.name + '-plain.bin')).write_bytes(out)
    print('plain head 64:', out[:64].hex())
    # locate pixel payload: try every plausible header skip
    for skip in range(0, 17):
        data = out[skip:]
        if len(data) < 7684:
            continue
        # 6->4 12-bit decode (Sigfrodr rule)
        px = []
        for i2 in range(0, len(data) - 6 + 1, 6):
            c = data[i2:i2+6]
            px += [((c[0] & 0xf) << 8) | c[1], (c[3] << 4) | (c[0] >> 4),
                   ((c[5] & 0xf) << 8) | c[2], (c[4] << 4) | (c[5] >> 4)]
            if len(px) >= 5120:
                break
        if len(px) < 5120:
            continue
        v = px[:5120]
        lo, hi = min(v), max(v)
        print(f'skip={skip}: decoded 5120 px, min={lo} max={hi} spread={hi-lo}')
        if hi - lo > 500:  # contrasty = likely real image
            # write 16-bit PGM + PNG
            pgm = PFX.parent / f'{PFX.name}-img-skip{skip}.pgm'
            with open(pgm, 'wb') as f:
                f.write(f'P5 64 80 65535\n'.encode())
                for y in range(80):
                    for x in range(64):
                        val = v[y * 64 + x]
                        f.write(bytes([val >> 8, val & 0xff]))
            # downscale to 8-bit PNG (orientation: rows as-is)
            png = PFX.parent / f'{PFX.name}-img-skip{skip}.png'
            w8 = [max(0, min(255, (val - lo) * 255 // max(1, hi - lo))) for val in v]
            raw = b''
            for y in range(80):
                raw += b'\x00' + bytes(w8[y * 64:(y + 1) * 64])
            def chunk(tag, data):
                c = tag + data
                return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
            hdr = b'\x89PNG\r\n\x1a\n'
            ihdr = struct.pack('>IIBBBBB', 64, 80, 8, 0, 0, 0, 0)
            png_data = hdr + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
            png.write_bytes(png_data)
            print(f'  wrote {pgm.name} and {png.name}')
    print('done')
else:
    print('frame is not TLS-wrapped; saved:', PFX.name + '-frame.bin')
    (PFX.parent / (PFX.name + '-frame.bin')).write_bytes(frame)
