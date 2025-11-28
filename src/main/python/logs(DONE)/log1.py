import re

pattern = re.compile(r'(?P<ip>\d+(?:\.\d+){3})')

unique_ips = set()

with open("access.log") as f:
    for line in f:
        match = pattern.match(line)
        if match:
            unique_ips.add(match.group("ip"))

print(len(unique_ips))