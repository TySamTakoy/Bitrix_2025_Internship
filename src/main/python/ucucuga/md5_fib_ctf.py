#!/usr/bin/env python3
"""
md5_fib_ctf.py

Вычисляет MD5 от конкатенации байт/частей файла согласно разным
интерпретациям "file[1]+file[2]+file[3]+file[5]+file[8]+...".

Требует: requests
pip install requests

Примеры:
  python md5_fib_ctf.py --url https://ucucuga.bxctf.ru/32tb --mode single-1based
  python md5_fib_ctf.py --url https://ucucuga.bxctf.ru/32tb --mode single-0based
  python md5_fib_ctf.py --url https://ucucuga.bxctf.ru/32tb --mode modulo --max-terms 10000
  python md5_fib_ctf.py --url https://ucucuga.bxctf.ru/32tb --mode prefixes-1based --max-prefixes 20 --max-total-bytes 1000000
"""

import argparse
import hashlib
import math
import sys
from typing import Iterator, List, Tuple

import requests

# -------------------- Utilities --------------------

def get_remote_file_size_and_range_support(session: requests.Session, url: str, timeout: int = 15) -> Tuple[int, bool]:
    """
    Возвращает (size, supports_range)
    Опытный путь: HEAD -> Content-Length и проверка Accept-Ranges / наличие Content-Range с ranged GET.
    """
    r = session.head(url, allow_redirects=True, timeout=timeout)
    cl = r.headers.get("Content-Length")
    size = int(cl) if cl and cl.isdigit() else None

    # Проверим header Accept-Ranges
    accept = r.headers.get("Accept-Ranges", "")
    if accept.lower() in ("bytes", "none"):
        supports = accept.lower() == "bytes"
    else:
        supports = False

    # Если размер не определён или неясно про Range — попробуем tiny ranged GET
    if size is None or not supports:
        r2 = session.get(url, headers={"Range": "bytes=0-0"}, stream=True, allow_redirects=True, timeout=timeout)
        # Content-Range: bytes 0-0/123456
        cr = r2.headers.get("Content-Range")
        if cr and "/" in cr:
            try:
                size = int(cr.split("/")[-1])
            except Exception:
                pass
        # Если мы получили 206 — поддержка range подтверждена
        if r2.status_code == 206:
            supports = True
        # If server returned 200 and provided Content-Length, we have size but no Range support
        if r2.status_code == 200 and size is None:
            cl2 = r2.headers.get("Content-Length")
            if cl2 and cl2.isdigit():
                size = int(cl2)
        r2.close()

    if size is None:
        raise RuntimeError("Не удалось определить размер файла. Сервер не дал Content-Length/Content-Range.")
    return size, supports

def fib_generator(start_variant: str = "1,2") -> Iterator[int]:
    """
    Генератор Фибоначчи. Поддерживает два старта:
      "1,2" -> 1,2,3,5,8,... (подходил для 1-based в ранних сообщениях)
      "0,1" -> 0,1,1,2,3,5,...
    """
    if start_variant == "1,2":
        a, b = 1, 2
        while True:
            yield a
            a, b = b, a + b
    else:
        a, b = 0, 1
        while True:
            yield a
            a, b = b, a + b

def fib_indices_up_to_file(size: int, zero_based: bool = False) -> List[int]:
    """
    Возвращает список индексов Фибоначчи, которые находятся в пределах файла.
    Если zero_based==False => возвращаем 1-based индексы (1..size).
    Если zero_based==True  => возвращаем 0-based индексы (0..size-1).
    """
    indices = []
    gen = fib_generator("0,1" if zero_based else "1,2")
    limit = size - 1 if zero_based else size
    for f in gen:
        if f > limit:
            break
        indices.append(f)
    return indices

def group_indices_by_span(indices: List[int], max_span: int) -> Iterator[List[int]]:
    """Группирует отсортированный список индексов в подсписки, span <= max_span."""
    if not indices:
        return
    group = [indices[0]]
    start = indices[0]
    for idx in indices[1:]:
        if idx - start + 1 <= max_span:
            group.append(idx)
        else:
            yield group
            group = [idx]
            start = idx
    if group:
        yield group

def fetch_range(session: requests.Session, url: str, start: int, end: int, timeout: int = 60) -> bytes:
    """Запрашивает bytes=start-end включительно. Ожидаем 206 Partial Content."""
    headers = {"Range": f"bytes={start}-{end}"}
    r = session.get(url, headers=headers, allow_redirects=True, stream=True, timeout=timeout)
    if r.status_code == 206:
        data = r.content
        r.close()
        return data
    elif r.status_code == 200:
        r.close()
        raise RuntimeError("Сервер вернул 200 OK на ranged запрос — он не поддерживает Range, отказ во избежание скачивания всего файла.")
    else:
        r.close()
        raise RuntimeError(f"HTTP {r.status_code} при запросе диапазона {start}-{end}")

# -------------------- Modes Implementations --------------------

def mode_single_bytes(session: requests.Session, url: str, size: int, zero_based: bool, max_span: int) -> str:
    """
    Берём одиночные байты с индексами Фибоначчи (в порядке возрастания индекса),
    и MD5 от их конкатенации.
    zero_based: True/False (0-based или 1-based).
    """
    indices = fib_indices_up_to_file(size, zero_based=zero_based)
    if not indices:
        return hashlib.md5(b"").hexdigest()
    # convert to 0-based positions for HTTP Range
    positions = [i if zero_based else i - 1 for i in indices]
    md5 = hashlib.md5()
    for group in group_indices_by_span(positions, max_span=max_span):
        s = group[0]
        e = group[-1]
        chunk = fetch_range(session, url, s, e)
        for p in group:
            md5.update(bytes([chunk[p - s]]))
    return md5.hexdigest()

def mode_modulo(session: requests.Session, url: str, size: int, max_terms: int, max_span: int) -> str:
    """
    Берём первые max_terms чисел Фибоначчи, для каждого f -> pos = f % size (0-based),
    затем md5 от байтов в порядке этих fib (то есть по порядку генерации).
    """
    if size <= 0:
        raise RuntimeError("Неверный размер файла.")
    md5 = hashlib.md5()
    gen = fib_generator("1,2")
    # Соберём позиции (в порядке генерации). Мы не будем дедублировать — это важно.
    positions = []
    count = 0
    for f in gen:
        if count >= max_terms:
            break
        pos = f % size
        positions.append(pos)
        count += 1
    # Чтобы сократить запросы, сгруппируем по span, но нужно извлекать в порядке positions.
    # Сначала сделаем план: сгруппируем уникальные позиции по span и запомним mapping.
    # Для простоты — сделаем группировку в порядке возрастания позиций, потом при сборке
    # будем выбирать байты в порядке исходного positions.
    unique_sorted = sorted(set(positions))
    # Map pos -> byte
    pos_to_byte = {}
    for group in group_indices_by_span(unique_sorted, max_span=max_span):
        s = group[0]
        e = group[-1]
        chunk = fetch_range(session, url, s, e)
        for p in group:
            pos_to_byte[p] = chunk[p - s]
    # Теперь обновим md5 в порядке positions
    for p in positions:
        md5.update(bytes([pos_to_byte[p]]))
    return md5.hexdigest()

def mode_prefixes(session: requests.Session, url: str, size: int, zero_based: bool, max_prefixes: int, max_total_bytes: int) -> str:
    """
    Интерпретация: md5(file[:1] + file[:2] + file[:3] + file[:5] + ...)
    (т.е. конкатенация первых N-байт-фрагментов).
    ВАЖНО: такой режим может потребовать огромного трафика — скрипт имеет защиты:
      - max_prefixes: количество префиксов (по числам Фиб)
      - max_total_bytes: верхний предел общего объёма, который мы готовы скачать
    Реализация: мы формируем список префикс-диапазонов, объединяем их в минимальные ranged запросы,
    затем извлекаем нужные части и строим MD5.
    """
    # сформируем list префиксов L = [1,2,3,5,8,...] (1-based или 0-based)
    fibs = fib_indices_up_to_file(size, zero_based=zero_based)
    if not fibs:
        return hashlib.md5(b"").hexdigest()
    fibs = fibs[:max_prefixes]
    # Преобразуем в exclusive end offsets (0-based ends): prefix k -> need bytes [0..k-1] (if 1-based),
    # if zero_based and fib gives 0 as first, file[:0] is empty; handle accordingly.
    prefix_ends = []
    for f in fibs:
        if zero_based:
            # f is a 0-based index that we interpret as "prefix length = f+1"? Ambiguity.
            # Мы трактуем "file[0]" как первый байт if zero_based==True, поэтому prefix length = f+1
            plen = f + 1
        else:
            plen = f
        if plen <= 0:
            continue
        prefix_ends.append(plen - 1)  # convert to inclusive end 0-based
    if not prefix_ends:
        return hashlib.md5(b"").hexdigest()

    # общий размер который потребуется, при наихудшем раскладе если загрузить каждый префикс отдельно:
    # однако мы будем объединять диапазоны. Посчитаем сумму уникальных байт, которую нужно будет скачать:
    unique_needed = prefix_ends[-1] + 1
    if unique_needed > max_total_bytes:
        raise RuntimeError(f"Запрошено {unique_needed} байт для префиксов, что больше лимита max_total_bytes={max_total_bytes}.")

    # Скачаем contiguous chunk [0 .. prefix_ends[-1]] одним запросом (если он не слишком велик)
    chunk = fetch_range(session, url, 0, prefix_ends[-1])
    md5 = hashlib.md5()
    # Теперь в порядке префиксов добавляем соответствующие первые plen байт
    for end_incl in prefix_ends:
        md5.update(chunk[0:end_incl + 1])
    return md5.hexdigest()

# -------------------- CLI --------------------

def parse_args():
    p = argparse.ArgumentParser(description="MD5 from Fibonacci-byte selections (CTF helper).")
    p.add_argument("--url", required=True, help="URL файла (HTTP/HTTPS).")
    p.add_argument("--mode", required=True, choices=[
        "single-1based", "single-0based", "modulo", "prefixes-1based", "prefixes-0based"
    ], help="Режим подсчёта.")
    p.add_argument("--max-span", type=int, default=65536, help="Максимальный span (в байтах) для одного ranged запроса (по умолчанию 65536).")
    p.add_argument("--max-terms", type=int, default=200000, help="(для режима modulo) сколько первых fib чисел брать.")
    p.add_argument("--max-prefixes", type=int, default=50, help="(для режима prefixes) сколько префиксов по числам Фиб брать.")
    p.add_argument("--max-total-bytes", type=int, default=5_000_000, help="(для prefixes) максимум байт, которые готовы скачать.")
    return p.parse_args()

def main():
    args = parse_args()
    session = requests.Session()
    try:
        print("Определяю размер файла и поддержку Range...")
        size, supports_range = get_remote_file_size_and_range_support(session, args.url)
        print(f"Размер файла: {size} байт. Range поддерживается: {supports_range}")
        if not supports_range:
            print("Сервер не поддерживает Range-запросы — скрипт завершит работу, чтобы не скачивать весь файл.")
            sys.exit(1)

        if args.mode == "single-1based":
            print("Режим: одиночные байты 1-based (file[1], file[2], ...)")
            digest = mode_single_bytes(session, args.url, size, zero_based=False, max_span=args.max_span)
        elif args.mode == "single-0based":
            print("Режим: одиночные байты 0-based (file[0], file[1], ...)")
            digest = mode_single_bytes(session, args.url, size, zero_based=True, max_span=args.max_span)
        elif args.mode == "modulo":
            print(f"Режим: modulo (f % size), первых {args.max_terms} чисел Фиб.")
            digest = mode_modulo(session, args.url, size, max_terms=args.max_terms, max_span=args.max_span)
        elif args.mode == "prefixes-1based":
            print("Режим: префиксы 1-based (file[:1] + file[:2] + file[:3] + ...)")
            digest = mode_prefixes(session, args.url, size, zero_based=False,
                                   max_prefixes=args.max_prefixes, max_total_bytes=args.max_total_bytes)
        elif args.mode == "prefixes-0based":
            print("Режим: префиксы 0-based (интерпретация file[:f+1])")
            digest = mode_prefixes(session, args.url, size, zero_based=True,
                                   max_prefixes=args.max_prefixes, max_total_bytes=args.max_total_bytes)
        else:
            raise RuntimeError("Неизвестный режим.")
        print("MD5:", digest)
    finally:
        session.close()

if __name__ == "__main__":
    main()