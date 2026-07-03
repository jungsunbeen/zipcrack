#!/usr/bin/env python3
"""
zipcrack.py - ZipCrypto(구형 ZIP 암호화) 비밀번호 복구 도구

본인이 소유한, 비밀번호를 잊어버린 ZIP 파일을 복구하는 용도입니다.
표준 라이브러리만 사용하므로 별도 설치가 필요 없습니다 (Python 3).

주의:
  - AES 암호화(WinZip AES) ZIP에는 동작하지 않습니다. 구형 ZipCrypto 전용입니다.
  - 사용 전 스크립트가 "암호화 방식: ZipCrypto"라고 알려주면 진행 가능합니다.

사용법:
  python3 zipcrack.py <zip파일경로> [옵션]

옵션:
  --digits N       숫자 비밀번호를 최대 N자리까지 탐색 (기본 8)
  --wordlist FILE  줄 단위 단어 목록 파일을 추가로 시도
  --extract DIR    비밀번호를 찾으면 DIR 폴더에 압축 해제
  --no-numeric     숫자 브루트포스를 건너뛰고 단어 목록만 시도

예시:
  python3 zipcrack.py ~/Downloads/Real.zip
  python3 zipcrack.py ~/Downloads/Real.zip --digits 6 --extract ~/Downloads/out
  python3 zipcrack.py secret.zip --wordlist rockyou.txt --no-numeric
"""
import struct, sys, zipfile, os, time, argparse

# ---- CRC32 테이블 (ZipCrypto 키 스케줄용) ----
CRCTAB = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xedb88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    CRCTAB.append(_c)


def _crc32(c, b):
    return CRCTAB[(c ^ b) & 0xff] ^ (c >> 8)


def load_header(fn):
    """ZIP 첫 로컬 헤더를 읽어 암호화 여부/방식/검증바이트/암호헤더를 반환."""
    data = open(fn, "rb").read()
    i = data.find(b'PK\x03\x04')
    if i < 0:
        raise SystemExit("ZIP 로컬 헤더를 찾을 수 없습니다. 올바른 ZIP 파일인가요?")
    (sig, ver, flags, method, mtime, mdate, crc, csize, usize,
     fnlen, extralen) = struct.unpack('<IHHHHHIIIHH', data[i:i+30])
    encrypted = bool(flags & 0x01)
    is_aes = (method == 99)
    enc_start = i + 30 + fnlen + extralen
    enc_header = data[enc_start:enc_start+12]
    # 데이터 디스크립터(bit3)면 검증바이트=수정시각 상위, 아니면 CRC 상위바이트
    check_byte = ((mtime >> 8) & 0xff) if (flags & 0x08) else ((crc >> 24) & 0xff)
    return {
        "encrypted": encrypted, "is_aes": is_aes, "method": method,
        "flags": flags, "check_byte": check_byte, "enc_header": enc_header,
    }


def make_checker(enc_header, target):
    """비밀번호 후보의 검증바이트만 빠르게 계산 (1/256 확률로 통과 → 이후 정밀검증)."""
    def check(pwd_bytes):
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pwd_bytes:
            k0 = _crc32(k0, b)
            k1 = (k1 + (k0 & 0xff)) & 0xffffffff
            k1 = (k1 * 134775813 + 1) & 0xffffffff
            k2 = _crc32(k2, (k1 >> 24) & 0xff)
        last = 0
        for c in enc_header:
            t = (k2 | 2) & 0xffff
            d = c ^ (((t * (t ^ 1)) >> 8) & 0xff)
            k0 = _crc32(k0, d)
            k1 = (k1 + (k0 & 0xff)) & 0xffffffff
            k1 = (k1 * 134775813 + 1) & 0xffffffff
            k2 = _crc32(k2, (k1 >> 24) & 0xff)
            last = d
        return last == target
    return check


def confirm(fn, pwd_bytes):
    """실제 압축 해제로 비밀번호가 진짜 맞는지 확인 (CRC 검증 포함)."""
    try:
        with zipfile.ZipFile(fn) as zf:
            zf.read(zf.namelist()[0], pwd=pwd_bytes)
        return True
    except Exception:
        return False


def candidates_wordlist(path):
    common = [
        "1234","12345","123456","1234567","12345678","123456789","1234567890",
        "0000","1111","password","password1","qwerty","abc123","admin","letmein",
        "1q2w3e4r","1q2w3e4r5t","a1234567","asdf1234","qwer1234","iloveyou",
        "p@ssw0rd","Passw0rd","0721","1004","7777","1q2w3e4r!",
    ]
    seen = set()
    for w in common:
        for v in (w, w.capitalize(), w.upper(), w+"!", w+"1", w+"123"):
            if v not in seen:
                seen.add(v); yield v
    for y in range(1940, 2031):
        s = str(y)
        if s not in seen:
            seen.add(s); yield s
    if path:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.rstrip("\n\r")
                if w and w not in seen:
                    seen.add(w); yield w


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("zip")
    ap.add_argument("--digits", type=int, default=8)
    ap.add_argument("--wordlist")
    ap.add_argument("--extract")
    ap.add_argument("--no-numeric", action="store_true")
    a = ap.parse_args()

    if not os.path.exists(a.zip):
        raise SystemExit("파일이 없습니다: " + a.zip)

    info = load_header(a.zip)
    if not info["encrypted"]:
        raise SystemExit("이 ZIP은 암호화되어 있지 않습니다. 그냥 unzip 하세요.")
    if info["is_aes"]:
        raise SystemExit("AES 암호화 ZIP입니다. 이 도구로는 복구할 수 없습니다.")
    print("암호화 방식: ZipCrypto (복구 시도 가능)")
    print("검증바이트: 0x%02x\n" % info["check_byte"])

    check = make_checker(info["enc_header"], info["check_byte"])
    start = time.time(); tested = 0; found = None

    # 1) 단어 목록
    for w in candidates_wordlist(a.wordlist):
        tested += 1
        pb = w.encode("utf-8", "ignore")
        if check(pb) and confirm(a.zip, pb):
            found = w; break
    if found is None:
        print("단어 목록 실패 (%d개, %.1fs). 숫자 탐색으로 넘어갑니다..." % (tested, time.time()-start))

    # 2) 숫자 브루트포스
    if found is None and not a.no_numeric:
        for length in range(1, a.digits + 1):
            for num in range(10 ** length):
                s = str(num).zfill(length); tested += 1
                pb = s.encode()
                if check(pb) and confirm(a.zip, pb):
                    found = s; break
            if found is not None:
                break
            print("  %d자리 완료, 누적 %d개, %.1fs" % (length, tested, time.time()-start))

    if found is None:
        print("\n비밀번호를 찾지 못했습니다 (%d개 시도, %.1fs)." % (tested, time.time()-start))
        print("→ --digits 값을 늘리거나 --wordlist 로 사전을 추가해 보세요.")
        sys.exit(1)

    print("\n*** 비밀번호를 찾았습니다: %r ***" % found)
    print("시도 횟수: %d, 소요: %.1fs" % (tested, time.time()-start))

    if a.extract:
        os.makedirs(a.extract, exist_ok=True)
        with zipfile.ZipFile(a.zip) as zf:
            zf.extractall(a.extract, pwd=found.encode("utf-8", "ignore"))
        print("압축 해제 완료: %s" % a.extract)


if __name__ == "__main__":
    main()
