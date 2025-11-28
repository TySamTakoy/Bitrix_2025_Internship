#!/usr/bin/env python3
"""
Финальное решение CTF задачи - осмысленная фраза в leet speak
"""

import re


def check_all_patterns(key, debug=True):
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

    original = key
    current = key

    for i, pattern in enumerate(patterns):
        match = re.search(pattern, current)
        if debug:
            print(f"Pattern {i + 1}: {pattern}")
            print(f"Current: {repr(current)}")

        if not match:
            if debug:
                print(f"✗ NO MATCH")
            return False, i + 1

        current = match.group(0)
        if debug:
            print(f"✓ Match: {repr(current)}")
            print()

    success = (current == original)
    return success, 0


def leet_decode(text):
    """Декодируем leet speak для понимания фразы"""
    replacements = {
        '4': 'a',
        '3': 'e',
        '5': 's',
        '0': 'o',
        '1': 'i',
        '7': 't'
    }
    decoded = ''
    for char in text:
        decoded += replacements.get(char, char)
    return decoded


# Финальное решение - осмысленная фраза
solution = "Gr45t j0b y0u d1d 1t r5"

print("=== Final CTF Solution ===")
print(f"Testing: {repr(solution)}")
print(f"Leet decoded: {leet_decode(solution)}")
print()

success, failed_at = check_all_patterns(solution, debug=True)

if success:
    print(f"\n🎉 SUCCESS! Final solution found!")
    print(f"FLAG: {solution}")
    print(f"Meaning: {leet_decode(solution)}")
    print(f"\nUse in Perl script:")
    print(f"echo '{solution}' | perl script.pl")
else:
    print(f"\nFailed at pattern {failed_at}")