import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime
import itertools

LOG_PATH = r"E:/python/btrx_sec/.venv/logs/access.log"
LINES_PER_CHUNK = 50_000
MAX_WORKERS = min(32, (os.cpu_count() or 1) * 2)

def parse_chunk(lines):
    sums = defaultdict(int)
    for line in lines:
        try:
            parts = line.split('"')
            if len(parts) < 3:
                continue
            after_request = parts[2].strip()  # например: 200 4263 -
            fields = after_request.split()
            if len(fields) < 2:
                continue
            size_field = fields[1]
            # извлекаем timestamp между [ ]
            lb = line.find('[')
            rb = line.find(']', lb+1)
            if lb == -1 or rb == -1:
                continue
            timestamp_raw = line[lb+1:rb]  # '12/Dec/2015:18:25:11 +0100'
            # парсим в datetime чтобы нормализовать и затем вывести с timezone точно в том же формате
            try:
                dt = datetime.strptime(timestamp_raw, "%d/%b/%Y:%H:%M:%S %z")
            except Exception:
                # если парсинг не удался, попробуем взять первые 14 символов (dd/Mon/YYYY:HH)
                # и отдельно таймзону (последние 5 символов)
                if len(timestamp_raw) >= 20:
                    hour_part = timestamp_raw[:14]   # dd/Mon/YYYY:HH
                    tz_part = timestamp_raw[-5:]     # +ZZZZ
                    key = f"{hour_part} {tz_part}"
                    size = int(size_field) if size_field.isdigit() else 0
                    sums[key] += size
                continue
            # формируем ключ как 'dd/Mon/YYYY:HH +ZZZZ'
            key = dt.strftime("%d/%b/%Y:%H %z")
            size = int(size_field) if size_field.isdigit() else 0
            sums[key] += size
        except Exception:
            # игнорируем проблемные строки
            continue
    return sums

def read_in_chunks_lines(path, lines_per_chunk=LINES_PER_CHUNK):
    """Генератор, отдающий списки по lines_per_chunk строк."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        chunk = []
        for line in f:
            chunk.append(line)
            if len(chunk) >= lines_per_chunk:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

def merge_dicts(dicts):
    res = defaultdict(int)
    for d in dicts:
        for k, v in d.items():
            res[k] += v
    return res

def find_peak_hour(log_path):
    futures = []
    partials = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        for chunk in read_in_chunks_lines(log_path):
            futures.append(exe.submit(parse_chunk, chunk))

        for fut in as_completed(futures):
            partials.append(fut.result())

    totals = merge_dicts(partials)
    if not totals:
        return None, None

    peak_hour, peak_bytes = max(totals.items(), key=lambda kv: kv[1])
    return peak_hour, peak_bytes

if __name__ == "__main__":
    peak_hour, peak_bytes = find_peak_hour(LOG_PATH)
    print(peak_hour)