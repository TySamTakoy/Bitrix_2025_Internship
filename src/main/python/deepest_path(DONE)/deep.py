import zipfile
import os

zip_file = 'E:/python/btrx_sec/.venv/deepest_path/path.zip'

deepest_path = None
max_depth = -1

with zipfile.ZipFile(zip_file, 'r') as zf:
    for name in zf.namelist():
        # Убираем слэш в конце, если это папка
        clean_name = name.rstrip('/')
        # Подсчитываем глубину (количество разделителей)
        depth = clean_name.count('/')
        if depth > max_depth:
            max_depth = depth
            deepest_path = clean_name

print(f"Самый глубокий путь: {deepest_path}")
print(f"Глубина: {max_depth}")

