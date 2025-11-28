import re
from collections import Counter

log_pattern = re.compile(
    r'(?P<ip>\d+(?:\.\d+){3}).*"[^"]*"\s(?P<code>\d{3})\s'
)

errors = Counter()

with open("access.log") as f:
    for line in f:
        match = log_pattern.search(line)
        if match:
            ip, code = match.group("ip"), int(match.group("code"))
            if 400 <= code < 500:
                errors[ip] += 1

ip, num = errors.most_common(1)[0]
print(f"{ip}:{num}")