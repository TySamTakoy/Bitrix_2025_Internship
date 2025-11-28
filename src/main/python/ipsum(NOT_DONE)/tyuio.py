from PIL import Image
import numpy as np

# Загружаем изображение
img = Image.open('task_ipsum.jpg')

# Конвертируем в RGBA (с поддержкой прозрачности)
img = img.convert('RGBA')

# Преобразуем в numpy array для удобной работы
data = np.array(img)

# Создаем маску для черных пикселей (RGB = 0, 0, 0)
# Проверяем, что все три канала (R, G, B) равны 0
black_mask = (data[:, :, 0] == 0) & (data[:, :, 1] == 0) & (data[:, :, 2] == 0)

# Устанавливаем альфа-канал (прозрачность) в 0 для черных пикселей
data[black_mask, 3] = 0

# Создаем новое изображение из измененных данных
result = Image.fromarray(data)

# Сохраняем результат в PNG (поддерживает прозрачность)
result.save('lorem_no_black.png')

print('Готово! Черный цвет удален. Результат сохранен в lorem_no_black.png')