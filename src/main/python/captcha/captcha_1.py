# human_loop_captcha_spa.py
import os
import time
import csv
import base64
from pathlib import Path
from io import BytesIO
from PIL import Image
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import JavascriptException, WebDriverException

OUT_DIR = Path("captchas_spa")
OUT_DIR.mkdir(exist_ok=True)
RESULTS_CSV = Path("results_spa.csv")

BASE_URL = "https://captcha.bxctf.ru/"  # ваша страница
NUM_TO_SOLVE = 100
WAIT_FOR_NEW_CAPTCHA_SECONDS = 0.01  # сколько ждать обновления каптчи после отправки
PAGE_LOAD_TIMEOUT = 30

def find_captcha_element(driver):
    # Найдём canvas или img с намёком на captcha, либо первый видимый canvas/img
    try:
        # явные селекторы (попробовать наиболее вероятные)
        candidates = []
        candidates += driver.find_elements(By.CSS_SELECTOR, "canvas")
        candidates += driver.find_elements(By.CSS_SELECTOR, "img[id*='captcha'], img[src*='captcha']")
        candidates += driver.find_elements(By.TAG_NAME, "img")
        # вернуть первый видимый
        for el in candidates:
            try:
                if el.is_displayed():
                    return el
            except Exception:
                continue
    except Exception:
        pass
    return None

def element_to_image_bytes(driver, el):
    tag = el.tag_name.lower()
    if tag == "canvas":
        # получить dataURL через JS
        try:
            data_url = driver.execute_script("return arguments[0].toDataURL('image/png');", el)
        except JavascriptException:
            return None
        if data_url and data_url.startswith("data:image"):
            header, b64 = data_url.split(",", 1)
            return base64.b64decode(b64)
        return None
    else:
        src = el.get_attribute("src")
        if src and src.startswith("data:image"):
            header, b64 = src.split(",", 1)
            return base64.b64decode(b64)
        # fallback: screenshot элемента
        try:
            png = el.screenshot_as_png
            return png
        except Exception:
            return None

def save_image_bytes(bts, path: Path):
    with open(path, "wb") as f:
        f.write(bts)
    # try to open with PIL to ensure it's viewable
    try:
        img = Image.open(path)
        img.verify()
    except Exception:
        pass

def open_image(path: Path):
    try:
        img = Image.open(path)
        img.show()
    except Exception:
        print("Откройте вручную:", path)

def find_input_and_submit(driver, answer):
    # Находим видимые текстовые поля и пробуем отправить ответ
    try:
        inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input:not([type]) , input[type='search'], textarea")
        for inp in inputs:
            try:
                if not inp.is_displayed():
                    continue
                inp.clear()
                inp.send_keys(answer)
                # попытки найти кнопку
                try:
                    btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                    if btn.is_displayed():
                        btn.click()
                        return True
                except Exception:
                    pass
                try:
                    btn2 = driver.find_element(By.CSS_SELECTOR, "input[type='submit']")
                    if btn2.is_displayed():
                        btn2.click()
                        return True
                except Exception:
                    pass
                # отправим Enter
                from selenium.webdriver.common.keys import Keys
                inp.send_keys(Keys.ENTER)
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False

def get_image_fingerprint(driver, el):
    # Вернём строковый "отпечаток" изображения: для img - src, для canvas - dataURL hash
    tag = el.tag_name.lower()
    if tag == "img":
        src = el.get_attribute("src") or ""
        return ("img", src)
    elif tag == "canvas":
        try:
            data_url = driver.execute_script("return arguments[0].toDataURL('image/png');", el)
            return ("canvas", data_url or "")
        except Exception:
            return ("canvas", "")
    else:
        try:
            b = el.screenshot_as_png
            return ("pngbytes", str(len(b)) + ":" + str(hash(b)))
        except Exception:
            return ("unknown", "")

def main():
    chrome_opts = Options()
    # Запускаем в видимом режиме — вам нужно смотреть на каптчу
    # chrome_opts.add_argument("--headless=new")  # не используйте при ручном вводе
    driver = webdriver.Chrome(options=chrome_opts)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)

    try:
        driver.get(BASE_URL)
    except WebDriverException as e:
        print("Не удалось загрузить страницу:", e)
        driver.quit()
        return

    results = []
    for i in range(1, NUM_TO_SOLVE + 1):
        print(f"\n=== Итерация {i}/{NUM_TO_SOLVE} ===")
        # Найдём каптчу
        el = find_captcha_element(driver)
        if not el:
            print("Каптча-элемент не найден на странице. Проверьте селекторы/структуру.")
            time.sleep(2)
            el = find_captcha_element(driver)
            if not el:
                print("Отмена итерации.")
                break

        # снимок и отпечаток
        fingerprint_before = get_image_fingerprint(driver, el)
        img_bytes = element_to_image_bytes(driver, el)
        filename = OUT_DIR / f"captcha_{i:03d}.png"
        if img_bytes:
            save_image_bytes(img_bytes, filename)
            print("Сохранена каптча:", filename)
            open_image(filename)
        else:
            # fallback — сделать скрин всей страницы
            filename = OUT_DIR / f"page_{i:03d}.png"
            driver.save_screenshot(str(filename))
            print("Сохранён скрин страницы:", filename)
            open_image(filename)

        answer = input("Введите решение каптчи (обязателен ручной ввод) или пустую строку для пропуска: ").strip()
        submitted = False
        if answer:
            submitted = find_input_and_submit(driver, answer)
            print("Ответ отправлен:", submitted)
        else:
            print("Пропускаем отправку.")

        # Логируем текущее состояние и ждём обновления каптчи (или flag)
        start = time.time()
        changed = False
        new_fingerprint = fingerprint_before
        while time.time() - start < WAIT_FOR_NEW_CAPTCHA_SECONDS:
            time.sleep(0.5)
            try:
                el2 = find_captcha_element(driver)
                if not el2:
                    continue
                new_fingerprint = get_image_fingerprint(driver, el2)
                if new_fingerprint != fingerprint_before:
                    changed = True
                    break
            except Exception:
                continue

        # Запись результата
        results.append({
            "index": i,
            "image": str(filename),
            "answer": answer,
            "submitted": submitted,
            "captcha_changed": changed,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "page_url": driver.current_url
        })

        with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["index","image","answer","submitted","captcha_changed","timestamp","page_url"])
            writer.writeheader()
            writer.writerows(results)

        print("Итерация завершена. captcha_changed =", changed)
        # короткая пауза, чтобы не создавать слишком частые действия
        time.sleep(0.3)

    driver.quit()
    print("\nГотово. Результаты записаны в:", RESULTS_CSV.resolve())
    print("Каталог с картинками:", OUT_DIR.resolve())

if __name__ == "__main__":
    main()