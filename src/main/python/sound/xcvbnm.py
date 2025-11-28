#!/usr/bin/env python3
# -*- coding: utf-8 -*-

dtmf_result = "8A4A3A0A3A5A2A4A0A4A7A0A7A6A0A2A2A5A5A0A6A3A0A6A2A9A2A3A"

# Убираем разделители 'A'
numbers = dtmf_result.replace('A', '')
print(f"Исходная последовательность: {dtmf_result}")
print(f"Числа без разделителей: {numbers}")
print(f"Длина: {len(numbers)} символов\n")

print("="*70)
print("ВАРИАНТЫ ДЕКОДИРОВАНИЯ:")
print("="*70)

# Вариант 1: ASCII из пар (двузначные коды)
print("\n1. ASCII декодирование (пары цифр):")
if len(numbers) % 2 == 0:
    try:
        ascii_pairs = ''.join(chr(int(numbers[i:i+2]))
                              for i in range(0, len(numbers), 2))
        print(f"   Результат: {ascii_pairs}")
        print(f"   Hex: {ascii_pairs.encode().hex()}")
    except Exception as e:
        print(f"   Ошибка: {e}")

# Вариант 2: ASCII из троек (трехзначные коды)
print("\n2. ASCII декодирование (тройки цифр):")
if len(numbers) % 3 == 0:
    try:
        ascii_triples = ''.join(chr(int(numbers[i:i+3]))
                                for i in range(0, len(numbers), 3))
        print(f"   Результат: {ascii_triples}")
    except Exception as e:
        print(f"   Ошибка: {e}")

# Вариант 3: Hex декодирование
print("\n3. HEX декодирование:")
try:
    hex_decoded = bytes.fromhex(numbers).decode('ascii')
    print(f"   Результат: {hex_decoded}")
except Exception as e:
    print(f"   Ошибка: {e}")

# Вариант 4: Octal (восьмеричная система)
print("\n4. Octal декодирование (тройки):")
if len(numbers) % 3 == 0:
    try:
        octal_decoded = ''.join(chr(int(numbers[i:i+3], 8))
                               for i in range(0, len(numbers), 3))
        print(f"   Результат: {octal_decoded}")
    except Exception as e:
        print(f"   Ошибка: {e}")

# Вариант 5: Decimal to text (каждая цифра - позиция в алфавите)
print("\n5. Цифра = позиция в алфавите (0=пробел):")
alphabet_map = {
    '0': ' ', '1': 'a', '2': 'b', '3': 'c', '4': 'd', '5': 'e',
    '6': 'f', '7': 'g', '8': 'h', '9': 'i'
}
alphabet_decoded = ''.join(alphabet_map.get(c, c) for c in numbers)
print(f"   Результат: {alphabet_decoded}")

# Вариант 6: Phone keypad T9 (как на старых телефонах)
print("\n6. T9 декодирование (клавиатура телефона):")
t9_map = {
    '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL',
    '6': 'MNO', '7': 'PQRS', '8': 'TUV', '9': 'WXYZ', '0': ' '
}
# Пробуем разбить на группы по разделителю 'A'
parts = dtmf_result.split('A')
print(f"   Части через A: {parts}")

t9_decoded = []
for part in parts:
    if part and part in t9_map:
        t9_decoded.append(t9_map[part][0])  # Берем первую букву
print(f"   Результат (первые буквы): {''.join(t9_decoded)}")

# Вариант 7: Группы цифр как коды
print("\n7. Разбивка через разделитель 'A' -> ASCII:")
parts_clean = [p for p in dtmf_result.split('A') if p]
print(f"   Части: {parts_clean}")
try:
    ascii_from_parts = ''.join(chr(int(p)) for p in parts_clean if p.isdigit())
    print(f"   ASCII из частей: {ascii_from_parts}")
except Exception as e:
    print(f"   Ошибка: {e}")

# Вариант 8: Base64 или другие кодировки
print("\n8. Попытка других форматов:")
import base64
try:
    # Может быть это base64 в числовом виде?
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    # Пробуем интерпретировать цифры как индексы
    pass
except:
    pass

# Вариант 9: Двоичная система (пары как биты)
print("\n9. Binary декодирование:")
try:
    # Преобразуем каждую пару в бинарный вид
    binary_str = ''.join(format(int(numbers[i:i+2]), '08b')
                        for i in range(0, len(numbers), 2))
    print(f"   Binary: {binary_str[:100]}...")
    # Пробуем декодировать по 8 бит
    binary_decoded = ''.join(chr(int(binary_str[i:i+8], 2))
                             for i in range(0, len(binary_str), 8))
    print(f"   Результат: {binary_decoded}")
except Exception as e:
    print(f"   Ошибка: {e}")

print("\n" + "="*70)
print("НАИБОЛЕЕ ВЕРОЯТНЫЕ ФЛАГИ:")
print("="*70)

# Проверяем все результаты на наличие паттернов флагов
candidates = [
    ("ASCII пары", ascii_pairs if len(numbers) % 2 == 0 else ""),
    ("Числа", numbers),
]

for name, value in candidates:
    if value and any(keyword in str(value).lower() for keyword in ['flag', 'ctf', '{', '}']):
        print(f"\n🚩 {name}: {value}")

print("\nПопробуйте отправить эти варианты:")
print(f"1. {numbers}")
if len(numbers) % 2 == 0:
    print(f"2. {ascii_pairs}")
print(f"3. {''.join(chr(int(p)) for p in parts_clean if p.isdigit() and int(p) < 128)}")