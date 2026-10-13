#!/usr/bin/env python3
"""matcher-sift.py — SIFT-based matcher evaluation on the cc-cap dataset.

Mirrors the goodix_sift approach (refs/mb13-godsquantum): SIFT keypoints with
RootSIFT descriptors, Lowe ratio test, geometric validation (RANSAC homography),
score = number of geometrically-consistent matches.

usage: matcher-sift.py <enroll_dir> <other_dir>

Reads /tmp/<dir>/capN.content.bin (7688 B). Requires numpy + cv2.
"""
import glob
import sys

import cv2
import numpy as np

W, H = 80, 61


def load(path):
    d = open(path, 'rb').read()
    px = []
    for i in range(8, len(d) - 5, 6):
        c = d[i:i + 6]
        px += [((c[0] & 0xf) << 8) | c[1], (c[3] << 4) | (c[0] >> 4),
               ((c[5] & 0xf) << 8) | c[2], (c[4] << 4) | (c[5] >> 4)]
    px = np.array(px[:5120], dtype=np.float32)
    img = px.reshape(80, 64).T[3:, :]  # 61x80 (display orientation, marker rows dropped)
    lo, hi = img.min(), img.max()
    img = (img - lo) * (255.0 / max(1.0, hi - lo))
    img = img.astype(np.uint8)
    # local contrast normalization: subtract heavy blur
    blur = cv2.GaussianBlur(img.astype(np.float32), (0, 0), 6)
    enh = np.clip(128 + (img.astype(np.float32) - blur) * 2.0, 0, 255).astype(np.uint8)
    return cv2.resize(enh, (320, 244), interpolation=cv2.INTER_CUBIC)


def descriptors(img):
    sift = cv2.SIFT_create(nfeatures=250, contrastThreshold=0.02)
    kp, des = sift.detectAndCompute(img, None)
    if des is not None:
        des = des / (des.sum(axis=1, keepdims=True) + 1e-7)  # RootSIFT
        des = np.sqrt(des)
    return kp, des


def match_score(kp1, d1, kp2, d2, ratio=0.8):
    if d1 is None or d2 is None or len(kp1) < 4 or len(kp2) < 4:
        return 0
    bf = cv2.BFMatcher()
    pairs = bf.knnMatch(d1, d2, k=2)
    good = [m for m, n in (p for p in pairs if len(p) == 2) if m.distance < ratio * n.distance]
    if len(good) < 4:
        return 0
    src = np.float32([kp1[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
    dst = np.float32([kp2[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)
    _, mask = cv2.findHomography(src, dst, cv2.RANSAC, 6.0)
    if mask is None:
        return 0
    return int(mask.sum())


enroll_dir = sys.argv[1] if len(sys.argv) > 1 else '/tmp/enroll'
other_dir = sys.argv[2] if len(sys.argv) > 2 else '/tmp/other'
enroll = [descriptors(load(p)) for p in sorted(glob.glob(f'{enroll_dir}/*.content.bin'))]
other = [descriptors(load(p)) for p in sorted(glob.glob(f'{other_dir}/*.content.bin'))]
print(f'enroll {len(enroll)} (kp: {[len(k) for k, _ in enroll]})')
print(f'other  {len(other)} (kp: {[len(k) for k, _ in other]})')

print('--- enroll vs enroll (genuine, pairwise max) ---')
gmins = []
for i in range(len(enroll)):
    best = max(match_score(*enroll[i], *enroll[j]) for j in range(len(enroll)) if j != i)
    gmins.append(best)
    print(f'  enroll[{i:2d}] best = {best}')
print('--- other vs enroll (impostor, max) ---')
imaxs = []
for j in range(len(other)):
    best = max(match_score(*other[j], *enroll[i]) for i in range(len(enroll)))
    imaxs.append(best)
    print(f'  other [{j}] best = {best}')
print(f'\nSEPARATION: genuine min {min(gmins)} vs impostor max {max(imaxs)}  (gap {min(gmins)-max(imaxs):+d})')
