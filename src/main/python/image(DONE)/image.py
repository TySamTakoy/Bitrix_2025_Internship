from PIL import Image
import numpy as np
from collections import Counter

# Загрузка изображения
img = Image.open("E:/python/btrx_sec/.venv/img/task_image.png").convert("RGBA")
data = np.array(img)

# Преобразуем пиксели в кортежи RGB (игнорируем альфа-канал)
pixels = [tuple(pixel[:3]) for row in data for pixel in row]

# Считаем, сколько раз встречается каждый цвет
color_counts = Counter(pixels)

# Создаем новый массив для результата
result = np.zeros_like(data)

# Проходим по всем пикселям и оставляем только уникальные цвета
for i in range(data.shape[0]):
    for j in range(data.shape[1]):
        color = tuple(data[i, j, :3])
        if color_counts[color] == 1:
            result[i, j] = data[i, j]  # сохраняем уникальный цвет
        else:
            result[i, j] = (0, 0, 0, 0)  # делаем прозрачным

# Сохраняем результат
output = Image.fromarray(result)
output.save("output.png")
