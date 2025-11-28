# НЕВЕРНОЕ РЕШЕНИЕ, ИСКАТЬ НУЖНО В ТАКОМ КЛЮЧЕ:

# Позиции слов в текстах сравниваются друг с другом,
# если отличаются - вывожу в консоль вместе с ссылкой

import sys
import time
import re
import urllib.parse as up
from collections import deque

import requests
from bs4 import BeautifulSoup

# Конфигурация
USER_AGENT = "Mozilla/5.0 (compatible; FlagFinder/1.0; +https://example.local)"
REQUEST_TIMEOUT = 10  # секунд
DELAY_BETWEEN_REQUESTS = 0.2  # секунды между запросами (чтобы не DDOS)
MAX_PAGES = 5000  # предельное количество страниц для обхода (защита от бесконечного сканирования)

# Паттерны, считающиеся флагом
FLAG_PATTERNS = [
    re.compile(r"flag\{.*?\}", re.IGNORECASE),
    re.compile(r"FLAG\{.*?\}"),
    re.compile(r"\bflag\b", re.IGNORECASE),
    re.compile(r"\bфлаг\b", re.IGNORECASE),
]


def is_same_domain(start_netloc, url):
    try:
        netloc = up.urlparse(url).netloc
        return netloc == start_netloc or netloc == ""
    except Exception:
        return False


def normalize_url(base, link):
    return up.urljoin(base, link.split("#")[0]).rstrip("/")


def find_flag_in_text(text):
    """Ищет по паттернам; возвращает первую найденную подсказку или None."""
    for p in FLAG_PATTERNS:
        m = p.search(text)
        if m:
            return m.group(0)
    return None


def crawl(start_url):
    parsed = up.urlparse(start_url)
    if not parsed.scheme:
        start_url = "http://" + start_url
        parsed = up.urlparse(start_url)
    base_netloc = parsed.netloc
    base_root = f"{parsed.scheme}://{parsed.netloc}"

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    visited = set()
    q = deque()
    q.append(start_url)
    visited.add(start_url)

    pages_count = 0

    while q and pages_count < MAX_PAGES:
        url = q.popleft()
        pages_count += 1
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            content_type = resp.headers.get("Content-Type", "")
            text = resp.text if "text" in content_type or content_type == "" else ""
        except Exception as e:
            print(f"[{pages_count}] ERROR fetching {url}: {e}")
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        print(f"[{pages_count}] Visited: {url} (status {resp.status_code})")

        # Ищем флаг в теле страницы (и в заголовке)
        flag = None
        search_space = " ".join([resp.text, resp.headers.get("Server", ""), resp.url, resp.reason or ""])
        flag = find_flag_in_text(search_space or "")

        if flag:
            print("\n=== FLAG FOUND ===")
            print(f"URL: {resp.url}")
            print(f"Match: {flag}\n")
            # Сохраняем страницу на диск
            filename = f"found_flag_page_{pages_count}.html"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(resp.text)
            print(f"Saved page to: {filename}")
            return {"url": resp.url, "match": flag, "saved": filename}

        # Если HTML, парсим ссылки
        if "html" in content_type.lower() or resp.text:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                # Проверяем также текстовые узлы на предмет возможного флага (кроме regex выше)
                # (дублирует find_flag_in_text, но приятная проверка)
                # Собираем все ссылки
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if not href:
                        continue
                    new_url = normalize_url(resp.url, href)
                    # Ограничиваемся тем же доменом (включая относительные ссылки)
                    if is_same_domain(base_netloc, new_url):
                        if new_url not in visited:
                            visited.add(new_url)
                            q.append(new_url)
                # можно добавить другие типы ссылок, если нужно (form action, script src и т.д.)
            except Exception as e:
                print(f"Parsing error for {url}: {e}")

        time.sleep(DELAY_BETWEEN_REQUESTS)

    print("Поиск завершён: флаг не найден (или достигнут лимит страниц).")
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python find_flag.py <start_url>")
        sys.exit(1)

    start_url = sys.argv[1]
    print(f"Start crawling from: {start_url}")
    result = crawl(start_url)
    if result:
        print("Успех:", result)
    else:
        print("Флаг не найден.")


if __name__ == "__main__":
    main()