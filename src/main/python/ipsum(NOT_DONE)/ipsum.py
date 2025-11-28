from PIL import Image
import numpy as np

# Загружаем изображение
img = Image.open('task_ipsum.jpg')
data = np.array(img)

print("Размер изображения:", img.size)
print("Режим:", img.mode)

# Метод 1: Инвертируем цвета (черное станет белым)
inverted = Image.fromarray(255 - data)
inverted.save('inverted.png')
print("✓ Создан inverted.png - инвертированные цвета")

# Метод 2: Увеличиваем контраст для почти черных пикселей
# Ищем пиксели, которые почти черные (но не совсем)
threshold = 10  # пиксели темнее этого значения
dark_mask = np.all(data < threshold, axis=2)
highlighted = data.copy()
highlighted[dark_mask] = [255, 0, 0]  # Красным
Image.fromarray(highlighted).save('dark_pixels.png')
print("✓ Создан dark_pixels.png - выделены темные пиксели")

# Метод 3: Бинаризация - делаем только черное и белое
gray = img.convert('L')
threshold = 1  # всё что не идеально черное - белое
binary = gray.point(lambda x: 0 if x < threshold else 255, '1')
binary.save('binary.png')
print("✓ Создан binary.png - бинарное изображение")

# Метод 4: Анализ LSB (младших битов) - популярный метод стеганографии
def extract_lsb(img_array, bit=0):
    # Извлекаем конкретный бит из каждого канала
    lsb = (img_array >> bit) & 1
    lsb = lsb * 255  # Делаем видимым
    return lsb

lsb_r = extract_lsb(data[:,:,0])
lsb_g = extract_lsb(data[:,:,1])
lsb_b = extract_lsb(data[:,:,2])

Image.fromarray(lsb_r.astype(np.uint8)).save('lsb_red.png')
Image.fromarray(lsb_g.astype(np.uint8)).save('lsb_green.png')
Image.fromarray(lsb_b.astype(np.uint8)).save('lsb_blue.png')
print("✓ Созданы lsb_*.png - LSB каждого канала")

# Метод 5: Проверяем разницу между соседними пикселями
diff = np.abs(np.diff(data.astype(np.int16), axis=1))
diff = np.concatenate([diff, np.zeros((diff.shape[0], 1, 3), dtype=diff.dtype)], axis=1)
diff = np.clip(diff * 50, 0, 255).astype(np.uint8)  # Усиливаем
Image.fromarray(diff).save('edges.png')
print("✓ Создан edges.png - границы и перепады")

# Метод 6: Только чисто черные пиксели (0,0,0)
pure_black = np.all(data == 0, axis=2)
result = np.ones_like(data) * 255
result[pure_black] = [0, 0, 0]
Image.fromarray(result.astype(np.uint8)).save('pure_black_only.png')
print("✓ Создан pure_black_only.png - только идеально черные пиксели")

print("\nПроверьте созданные файлы! Флаг должен быть в одном из них.")