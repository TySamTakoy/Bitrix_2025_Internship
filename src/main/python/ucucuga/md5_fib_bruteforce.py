#!/usr/bin/env python3
"""
md5_fib_exhaustive.py

Более исчерпывающий перебор интерпретаций "md5(file[1]+file[2]+file[3]+file[5]+...)".
Не скачивает весь файл (использует Range). Экономит запросы, группируя позиции.

Требует: requests
pip install requests
"""
import argparse
import hashlib
import base64
from typing import List, Dict, Tuple
import requests
import sys

# ---------------------- Helpers ----------------------

def get_size_and_range(session: requests.Session, url: str) -> Tuple[int, bool]:
    """Возвращает размер файла и поддерживает ли сервер Range."""
    r = session.head(url, allow_redirects=True, timeout=15)
    cl = r.headers.get("Content-Length")
    size = int(cl) if cl and cl.isdigit() else None
    accept = r.headers.get("Accept-Ranges", "")
    supports = accept.lower() == "bytes"
    if size is None or not supports:
        r2 = session.get(url, headers={"Range": "bytes=0-0"}, allow_redirects=True, stream=True, timeout=15)
        cr = r2.headers.get("Content-Range")
        if cr and "/" in cr:
            try:
                size = int(cr.split("/")[-1])
            except:
                pass
        if r2.status_code == 206:
            supports = True
        r2.close()
    if size is None:
        raise RuntimeError("Не удалось определить размер файла.")
    return size, supports

def fib_generator(variant: str):
    if variant == "1,2":
        a, b = 1, 2
    elif variant == "1,1":
        a, b = 1, 1
    else:
        a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b

def build_fib_list(limit: int, variant: str, max_terms: int) -> List[int]:
    res = []
    for i, f in enumerate(fib_generator(variant)):
        if i >= max_terms:
            break
        if f > limit:
            break
        res.append(f)
    return res

def unique_preserve_order(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def group_contiguous(sorted_positions: List[int]) -> List[Tuple[int,int]]:
    """Возвращает список (start,end) для contiguous ranges (inclusive)."""
    if not sorted_positions:
        return []
    ranges = []
    s = sorted_positions[0]
    e = s
    for p in sorted_positions[1:]:
        if p == e + 1:
            e = p
        else:
            ranges.append((s, e))
            s = p
            e = p
    ranges.append((s, e))
    return ranges

def fetch_positions_bytes(session: requests.Session, url: str, positions: List[int], timeout=60) -> Dict[int, int]:
    """
    positions: 0-based positions to fetch (arbitrary order).
    Возвращает dict pos -> byte (int 0..255).
    Выполняет минимальное число ranged запросов (объединяя contiguous позиции).
    """
    if not positions:
        return {}
    unique_sorted = sorted(set(positions))
    ranges = group_contiguous(unique_sorted)
    pos_to_byte = {}
    for s, e in ranges:
        headers = {"Range": f"bytes={s}-{e}"}
        r = session.get(url, headers=headers, stream=True, timeout=timeout)
        if r.status_code != 206:
            r.close()
            raise RuntimeError(f"Range request {s}-{e} returned {r.status_code}")
        data = r.content
        r.close()
        for offset, p in enumerate(range(s, e+1)):
            pos_to_byte[p] = data[offset]
    return pos_to_byte

# ---------------------- Representations ----------------------

def repr_variants_from_bytes(byte_seq: bytes) -> Dict[str, bytes]:
    """
    Возвращает словарь label -> bytes, которые мы будем хешировать.
    Включает популярные текстовые представления.
    """
    out = {}
    # raw bytes
    out["raw"] = byte_seq
    # hex lower/upper strings (encoded as ASCII)
    hexl = byte_seq.hex()
    out["hex_lower"] = hexl.encode('ascii')
    out["hex_upper"] = hexl.upper().encode('ascii')
    # base64 of raw bytes (ASCII)
    out["base64"] = base64.b64encode(byte_seq)
    # comma-separated decimal bytes (ASCII)
    decs = ",".join(str(b) for b in byte_seq)
    out["dec_comma"] = decs.encode('ascii')
    # concatenated decimal digits with no separator
    dec_concat = "".join(str(b) for b in byte_seq)
    out["dec_concat"] = dec_concat.encode('ascii')
    # utf-8 string (may be invalid) — keep bytes as-is for hashing but provide variant where we attempt to encode/decode
    try:
        u = byte_seq.decode('utf-8', errors='ignore').encode('utf-8')
    except:
        u = b""
    out["utf8_ignore"] = u
    # repr(list_of_ints)
    out["repr_list"] = repr(list(byte_seq)).encode('ascii')
    # hex bytes with 0x prefix separated by spaces: "0xAA 0xBB"
    out["hex0x_space"] = " ".join("0x{:02x}".format(b) for b in byte_seq).encode('ascii')
    # bytes reversed (raw)
    out["raw_reversed"] = byte_seq[::-1]
    return out

# ---------------------- Modes to try ----------------------

def generate_candidates(session: requests.Session, url: str, size: int, max_terms: int, try_modulo: bool, dedup_limit: int = 100000):
    candidates = []
    variants = ["1,2", "1,1", "0,1"]
    bases = [0,1]  # 0-based or 1-based
    dup_options = [True, False]
    orders = ["generation", "sorted", "reversed"]  # order of concatenation
    for variant in variants:
        for base in bases:
            limit = (size - 1) if base == 0 else size
            fibs = build_fib_list(limit, variant, max_terms)
            if not fibs:
                continue
            for keep_dup in dup_options:
                seq = fibs[:]
                if not keep_dup:
                    seq = unique_preserve_order(seq)
                # convert to 0-based positions
                if base == 0:
                    positions_zero = [f for f in seq]
                else:
                    positions_zero = [f - 1 for f in seq]
                # filter invalid
                positions_zero = [p for p in positions_zero if 0 <= p < size]
                if not positions_zero:
                    continue
                # create three orderings
                for ordmode in orders:
                    if ordmode == "generation":
                        concat_order = positions_zero
                    elif ordmode == "sorted":
                        concat_order = sorted(positions_zero)
                    else:  # reversed
                        concat_order = list(reversed(positions_zero))
                    # fetch bytes (we need all unique positions used)
                    pos_map = fetch_positions_bytes(session, url, concat_order)
                    # form byte sequence in concat_order
                    bseq = bytes(pos_map[p] for p in concat_order)
                    label = f"single-bytes variant={variant} base={'0' if base==0 else '1'} dup={keep_dup} order={ordmode}"
                    candidates.append((label, bseq))
    # modulo variants
    if try_modulo:
        for variant in variants:
            gen = fib_generator(variant)
            fibs = []
            for i, f in enumerate(gen):
                if i >= max_terms:
                    break
                fibs.append(f)
            if not fibs:
                continue
            positions_zero = [f % size for f in fibs]
            concat_order = positions_zero[:]  # keep generation order
            pos_map = fetch_positions_bytes(session, url, list(set(positions_zero)))
            bseq = bytes(pos_map[p] for p in concat_order)
            label = f"modulo variant={variant} terms={len(fibs)}"
            candidates.append((label, bseq))
    return candidates

# ---------------------- Main ----------------------

def compute_and_print(url: str, max_terms: int, try_modulo: bool):
    session = requests.Session()
    try:
        size, supports = get_size_and_range(session, url)
        print(f"File size: {size} bytes. Range supported: {supports}")
        if not supports:
            print("Сервер не поддерживает Range — прекращаем, чтобы не скачать весь файл.")
            return
        print("Генерирую кандидаты (это может занять пару секунд)...")
        cand = generate_candidates(session, url, size=size, max_terms=max_terms, try_modulo=try_modulo)
        seen_md5 = {}
        for label, bseq in cand:
            reps = repr_variants_from_bytes(bseq)
            for rlabel, rbytes in reps.items():
                md5h = hashlib.md5(rbytes).hexdigest()
                key = (md5h, rlabel)
                if md5h not in seen_md5:
                    seen_md5[md5h] = []
                seen_md5[md5h].append((label, rlabel, len(rbytes)))
        # print results unique md5s
        print("\nCandidates (unique MD5s):\n")
        for md5h, infos in seen_md5.items():
            print("----")
            print("MD5:", md5h)
            for info in infos:
                label, rlabel, bcount = info
                print(f"  mode: {label}, repr: {rlabel}, bytes_len: {bcount}")
        print("\nПопробуйте эти MD5 в CTF (с форматами flag{...} и без).")
    finally:
        session.close()

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="URL to file")
    p.add_argument("--max-terms", type=int, default=200, help="Max fib terms to generate (safety)")
    p.add_argument("--modulo", action="store_true", help="Also try f % size variants")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    try:
        compute_and_print(args.url, max_terms=args.max_terms, try_modulo=args.modulo)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
