import re
from datetime import datetime

pattern = re.compile(r'\[(?P<time>[^\]]+)\]')
times = []

with open("access.log") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            timestamp_str = match.group("time")
            dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            times.append(dt)

times.sort()

# Найти максимальную разницу между соседними временными метками
max_idle = max((t2 - t1).total_seconds() for t1, t2 in zip(times, times[1:]))
print(int(max_idle))
