from shakespearelang import Shakespeare
import sys

if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = 'first_play.spl'

try:
    with open(filename, 'r', encoding='utf-8') as f:
        code = f.read()

    print(f"Запуск файла: {filename}")
    play = Shakespeare(code)
    play.run()
    print("\nПрограмма завершена успешно!")

except Exception as e:
    print(f"Ошибка: {e}")