import hashlib
import requests
from typing import List, Iterator

def get_remote_file_size(session: requests.Session, url: str) -> int:
    """Попытка получить размер файла: сначала HEAD, иначе Range 0-0."""
    # 1) HEAD
    r = session.head(url, allow_redirects=True, timeout=30)
    cl = r.headers.get('Content-Length')
    if cl and cl.isdigit():
        return int(cl)
    # 2) Try a tiny ranged GET to read Content-Range
    r = session.get(url, headers={'Range': 'bytes=0-0'}, stream=True, allow_redirects=True, timeout=30)
    cr = r.headers.get('Content-Range')  # e.g. "bytes 0-0/123456789"
    if cr and '/' in cr:
        total = cr.split('/')[-1]
        if total.isdigit():
            return int(total)
    # 3) fallback: if Content-Length present on full GET (dangerous), don't proceed
    cl2 = r.headers.get('Content-Length')
    if cl2 and cl2.isdigit():
        return int(cl2)
    raise RuntimeError("Не удалось определить размер файла (сервер не вернул Content-Length/Content-Range).")

def fib_indices_up_to(max_inclusive: int) -> List[int]:
    """Возвращает список чисел Фибоначчи (1-based) <= max_inclusive.
       Начинаем последовательность: 1,2,3,5,... (как в задаче)."""
    if max_inclusive < 1:
        return []
    res = []
    a, b = 1, 2
    res.append(a)
    if b <= max_inclusive:
        res.append(b)
    while True:
        c = a + b
        if c > max_inclusive:
            break
        res.append(c)
        a, b = b, c
    return res

def group_indices_by_span(indices: List[int], max_span: int) -> Iterator[List[int]]:
    """Группирует отсортированный список индексов в подсписки так, чтобы span <= max_span.
       Span считается как (max_index - min_index + 1)."""
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

def compute_md5_fib(url: str, max_span: int = 65536, session: requests.Session = None) -> str:
    """
    Основная функция.
    :param url: URL большого файла (HTTP/HTTPS).
    :param max_span: максимальный span (байт) для одного Range-запроса; уменьшите, если сервер/сеть ненадёжны.
    :param session: опциональная requests.Session()
    :return: hex MD5 строки, соответствующей concat(file[fib_i]) по возрастанию fib_i.
    """
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    try:
        file_size = get_remote_file_size(session, url)
        if file_size <= 0:
            raise RuntimeError("Размер файла <= 0.")
        # Получаем все индексы Фибоначчи в пределах файла (1-based)
        indices = fib_indices_up_to(file_size)
        if not indices:
            return hashlib.md5(b'').hexdigest()

        # Группируем индексы в окна, чтобы уменьшить число запросов
        md5 = hashlib.md5()

        for group in group_indices_by_span(indices, max_span=max_span):
            start_idx = group[0]        # 1-based
            end_idx = group[-1]         # 1-based
            # Конвертация в 0-based для заголовка Range
            range_start = start_idx - 1
            range_end = end_idx - 1
            headers = {'Range': f'bytes={range_start}-{range_end}'}
            r = session.get(url, headers=headers, stream=True, timeout=60)
            # Ожидаем Partial Content (206). Если сервер вернул 200 и весь файл — не делаем этого (чтобы не скачать всё).
            if r.status_code == 206:
                chunk = r.content  # небольшой кусок (<= max_span)
                # извлечь только нужные позиции в порядке группы и обновить md5
                # относительная позиция = idx - start_idx
                extracted = bytearray(len(group))
                for i, idx in enumerate(group):
                    rel = idx - start_idx
                    extracted[i] = chunk[rel]
                md5.update(extracted)
            elif r.status_code == 200:
                # Сервер проигнорировал Range и вернул весь файл => опасно загружать
                r.close()
                raise RuntimeError("Сервер не поддерживает Range-requests (вернул 200 OK). Отказано во избежание скачивания всего файла.")
            else:
                r.close()
                raise RuntimeError(f"Ошибка HTTP при запросе диапазона {range_start}-{range_end}: статус {r.status_code}")
        return md5.hexdigest()
    finally:
        if close_session:
            session.close()

if __name__ == "__main__":
    url = "https://ucucuga.bxctf.ru/32tb"   # замените на свой URL
    try:
        digest = compute_md5_fib(url, max_span=65536)
        print("MD5 (конкатенация байт по Фибоначчи):", digest)
    except Exception as e:
        print("Ошибка:", e)
