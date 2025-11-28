import re
from datetime import datetime, timedelta
from collections import defaultdict

# Путь к файлу с логами
log_file = "access.log"

# Регекс для извлечения IP и даты
log_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+) - - \[(\d{2}/[A-Za-z]{3}/\d{4})')

# Словарь: ip -> set(даты)
ip_dates = defaultdict(set)

# Чтение логов
with open(log_file, 'r') as f:
    for line in f:
        match = log_pattern.match(line)
        if match:
            ip = match.group(1)
            date_str = match.group(2)
            # Преобразуем в datetime
            date_obj = datetime.strptime(date_str, "%d/%b/%Y").date()
            ip_dates[ip].add(date_obj)

# Функция поиска максимальной серии подряд
def max_consecutive_days(dates_set):
    if not dates_set:
        return 0, None, None
    dates = sorted(dates_set)
    max_streak = 1
    current_streak = 1
    start = dates[0]
    end = dates[0]
    streak_start = dates[0]

    for i in range(1, len(dates)):
        if dates[i] == dates[i-1] + timedelta(days=1):
            current_streak += 1
        else:
            current_streak = 1
            streak_start = dates[i]
        if current_streak > max_streak:
            max_streak = current_streak
            start = streak_start
            end = dates[i]
    return max_streak, start, end

# Поиск IP с максимальной серией
best_ip = None
best_streak = 0
best_start = None
best_end = None

for ip, dates_set in ip_dates.items():
    streak, start, end = max_consecutive_days(dates_set)
    if streak > best_streak:
        best_streak = streak
        best_ip = ip
        best_start = start
        best_end = end

# Вывод в формате ip|num_days|a|b
if best_ip:
    print(f"{best_ip}|{best_streak}|{best_start.strftime('%d/%b/%Y')}|{best_end.strftime('%d/%b/%Y')}")
else:
    print("No data found")
