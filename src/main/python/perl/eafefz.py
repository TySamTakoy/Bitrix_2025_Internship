#!/usr/bin/env python3
"""
Финальный solver с конкретными тестами
"""
import re

patterns = [
    r'.*5.*[^1-9].',
    r'[A-R]{1}.{4} \D+\d{2} \S+',
    r'[^H-Z]r[0-9]{2}t\s\S{5}\st[0-1]{3}',
    r'[^A-Fk-m0-9 ].[1-5].{12,}1',
    r'.{9}[502][364]\s\w0+ ?\d',
    r'[^0-25-9]{5}[ \f\n\r\t\v][a-r]+[^02468]+\s.{4}',
    r'[A-Za-z]+[^4][^3][p-t ]{3}[ar]+\d\d[ t]+\d+$',
    r'\D{2}\d{2}\D\s[^qrs][A-Ma-k][b-t]\d{2}\s.+',
    r'[\w\W]*r5[\w\W]*',
    r'\w* ?\w* \w*'
]

def test(s):
    key = s
    for i, p in enumerate(patterns):
        m = re.search(p, key)
        if not m:
            return False, i
        key = m.group(0)
    return key == s, -1

# Конкретные кандидаты
test_strings = [
    "Dr52t aaaaa t001 ar99 t 9",
    "Ar52t aaaaa t001 ar99 t 9",
    "Br52t bbbbb t010 ar88 t 8",
    "Cr52t ccccc t011 ar77 t 7",
    "Er52t eeeee t101 ar55 t 5",
    "Fr52t fffff t000 ar44 t 4",
    "Gr52t ggggg t110 ar33 t 3",
    "Dr50t aaaaa t001 ar99 t 9",
    "Dr51t aaaaa t000 ar99 t 1",
    "Pr52t xxxxx t101 ar66 t 6",
]

print("[*] Testing specific candidates:\n")

for ts in test_strings:
    valid, idx = test(ts)
    status = "✓ VALID" if valid else f"✗ Failed at P{idx}"
    print(f"  {ts:40} -> {status}")

print("\n[*] If none work above, trying brute force(NOT_DONE)...\n")

found = False
for first in 'ABCDEFG':
    if found:
        break
    for d1 in '0123456789':
        if found:
            break
        for d2 in '0123456789':
            if found:
                break
            for mid_char in 'abcdefghijklmnopqrstuvwxyz':
                if found:
                    break
                mid = mid_char * 5
                for t_bits in ['t000', 't001', 't010', 't011', 't100', 't101', 't110', 't111']:
                    if found:
                        break
                    for ard1 in '0123456789':
                        for ard2 in '0123456789':
                            for sep in [' t ', ' ']:
                                for final_d in '123456789':
                                    cand = f"{first}r{d1}{d2}t {mid} {t_bits} ar{ard1}{ard2}{sep}{final_d}"
                                    valid, idx = test(cand)
                                    if valid:
                                        print(f"[+++] SOLUTION FOUND:\n{cand}\n")
                                        found = True
                                        break

if not found:
    print("[-] Solution not found with this approach")
    print("[*] The solution might require a completely different structure")