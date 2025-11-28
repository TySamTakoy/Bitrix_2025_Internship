"""
RSA Decryption - Экзотические атаки и последняя надежда
"""

from sympy import mod_inverse, gcd, sqrt_mod, jacobi_symbol
from math import isqrt

def check_special_relationship(N, E, C):
    """Проверяем специальные математические связи между параметрами"""
    print("=" * 70)
    print("ПРОВЕРКА СПЕЦИАЛЬНЫХ СВЯЗЕЙ МЕЖДУ ПАРАМЕТРАМИ")
    print("=" * 70)

    # Проверка 1: E + N = ?
    sum_en = E + N
    print(f"\nE + N = {sum_en}")

    # Проверка 2: E - N = ?
    diff_en = abs(E - N)
    print(f"|E - N| = {diff_en}")

    # Проверка 3: E * 2 mod N
    e2 = (E * 2) % N
    print(f"(E * 2) mod N = {e2}")

    # Проверка 4: Может E = kφ(N) + d для малого k?
    # Если E очень большое, то E ≈ φ(N)
    # Попробуем E = φ(N) + d где d мало

    print("\n" + "-" * 70)
    print("Проверка: E ≈ φ(N) + d (малое d)")
    print("-" * 70)

    # φ(N) ≈ N - 2√N для RSA
    sqrt_n = isqrt(N)
    phi_approx = N - 2 * sqrt_n

    # Если E = k*φ(N) + d, то d = E mod φ(N)
    # Но φ(N) неизвестно точно

    # Пробуем разные k
    for k in range(1, 10):
        # Предполагаем E = k*φ(N) - d или E = k*φ(N) + d

        # Вариант 1: d = k*φ(N) - E
        d_candidate = k * phi_approx - E
        if d_candidate > 0 and d_candidate < 1000000:
            print(f"  k={k}: пробуем d = {d_candidate}")
            try:
                M = pow(C, d_candidate, N)
                if pow(M, E, N) == C:
                    print(f"\n✓✓✓ НАЙДЕНО! d = {d_candidate}, k = {k}")
                    return M, d_candidate
            except:
                pass

        # Вариант 2: d = E - k*φ(N)
        d_candidate = E - k * phi_approx
        if d_candidate > 0 and d_candidate < 1000000:
            print(f"  k={k}: пробуем d = {d_candidate}")
            try:
                M = pow(C, d_candidate, N)
                if pow(M, E, N) == C:
                    print(f"\n✓✓✓ НАЙДЕНО! d = {d_candidate}, k = {k}")
                    return M, d_candidate
            except:
                pass

    return None, None

def small_d_bruteforce(N, E, C, max_d=1000000):
    """Брутфорс малых значений d"""
    print("\n" + "=" * 70)
    print(f"БРУТФОРС МАЛЫХ d (до {max_d})")
    print("=" * 70)

    for d in range(3, max_d, 2):
        if d % 100000 == 0:
            print(f"  Проверено до d={d:,}...")

        try:
            M = pow(C, d, N)
            # Проверяем: M^E = C?
            if pow(M, E, N) == C:
                print(f"\n✓✓✓ НАЙДЕНО d = {d}!")
                return M, d
        except:
            pass

    print("✗ Малые d не найдены")
    return None, None

def check_factordb_online(N):
    """Последняя попытка через factordb с requests"""
    print("\n" + "=" * 70)
    print("ЗАПРОС К FACTORDB (через API)")
    print("=" * 70)

    try:
        import requests
        url = f"http://factordb.com/api?query={N}"
        response = requests.get(url, timeout=30)
        data = response.json()

        print(f"Статус FactorDB: {data.get('status', 'unknown')}")

        if 'factors' in data:
            factors = data['factors']
            print(f"Найдено {len(factors)} факторов")

            if len(factors) >= 2:
                factor_values = [int(f[0]) for f in factors]

                # Пробуем разные комбинации
                for i in range(len(factor_values)):
                    for j in range(i+1, len(factor_values)):
                        p, q = factor_values[i], factor_values[j]
                        if p * q == N:
                            print(f"\n✓ Найдена факторизация!")
                            return p, q

                        # Может N = p^a * q^b?
                        for a in range(1, 5):
                            for b in range(1, 5):
                                if (p ** a) * (q ** b) == N:
                                    print(f"\n✓ Найдена факторизация: N = {p}^{a} * {q}^{b}")
                                    return p ** a, q ** b

        print("FactorDB не предоставил полезную информацию")
    except Exception as e:
        print(f"Ошибка при обращении к FactorDB: {e}")

    return None, None

def coppersmith_attack_hint(N, E):
    """Подсказка для атаки Копперсмита"""
    print("\n" + "=" * 70)
    print("АТАКА КОППЕРСМИТА")
    print("=" * 70)
    print("Эта атака работает когда:")
    print("- Известны старшие или младшие биты p")
    print("- Известна часть секретного ключа d")
    print("- Есть линейная зависимость между p и q")
    print("\nДля этой атаки нужна библиотека SageMath")
    print("Используйте RsaCtfTool с --attack coppersmith")

def final_analysis(N, E, C):
    """Финальный математический анализ"""
    print("\n" + "=" * 70)
    print("ФИНАЛЬНЫЙ АНАЛИЗ")
    print("=" * 70)

    print(f"\nN = {N}")
    print(f"E = {E}")
    print(f"C = {C}")

    print(f"\nN в hex: {hex(N)[:80]}...")
    print(f"E в hex: {hex(E)[:80]}...")
    print(f"C в hex: {hex(C)[:80]}...")

    # Проверяем последние цифры
    print(f"\nN mod 10 = {N % 10}")
    print(f"E mod 10 = {E % 10}")
    print(f"C mod 10 = {C % 10}")

    # Проверяем на степени
    for exp in [2, 3, 4, 5]:
        root = int(N ** (1/exp))
        if root ** exp == N:
            print(f"\n⚠ N = {root}^{exp}!")
            return

def main():
    N = 303064257616594251424484693201721476326759723722885142397172522785244850162149467777077262616763634666043370043776556377672612393694156650080294923491656774270297835830691819365631476152833243761676761284450810253195741763806661956295880535771914878382524356687259890302543028387814854963781707333811249106203

    E = 1405503029963965366473060336278118676167365932101849846592340941002469822121482629544939263777211225214548125175158938184832578780549381159155884766186385061466984086929191614013042541332483293375541857384248786618653404532946005231602802774811616021063382934908080793725850332158385377806909483417117493355

    C = 191932712726136813275509765328051860284771162560985391987970739157524768285407205222381233734157003649376435098624529812051431218732344023506441648455534104178901841700967549505903536787487557128943670260059913188607644075604433223749859366948231822820394134158831969796158146360929730108156141990922747247678

    print("=" * 70)
    print("RSA DECRYPTION - ЭКЗОТИЧЕСКИЕ АТАКИ")
    print("=" * 70)

    # 1. Проверяем специальные связи
    M, d = check_special_relationship(N, E, C)
    if M:
        print_result(M, d)
        return

    # 2. Брутфорс малых d
    M, d = small_d_bruteforce(N, E, C, max_d=10000000)
    if M:
        print_result(M, d)
        return

    # 3. Последняя попытка через FactorDB
    p, q = check_factordb_online(N)
    if p and q:
        phi = (p - 1) * (q - 1)
        d = mod_inverse(E, phi)
        M = pow(C, d, N)
        print_result(M, d, p, q)
        return

    # 4. Финальный анализ
    final_analysis(N, E, C)

    # 5. Атака Копперсмита
    coppersmith_attack_hint(N, E)

    print("\n" + "=" * 70)
    print("🔴 ВСЕ МЕТОДЫ ИСЧЕРПАНЫ")
    print("=" * 70)
    print("\n⚡ КРИТИЧЕСКИ ВАЖНО: Используйте RsaCtfTool!")
    print("\nУстановка и запуск:")
    print("-" * 70)
    print("git clone https://github.com/RsaCtfTool/RsaCtfTool.git")
    print("cd RsaCtfTool")
    print("pip3 install -r requirements.txt")
    print()
    print("python3 RsaCtfTool.py \\")
    print(f"  -n {N} \\")
    print(f"  -e {E} \\")
    print("  --private --attack all")
    print("-" * 70)
    print("\nRsaCtfTool включает 50+ атак на RSA, включая:")
    print("• Boneh-Durfee (требует SageMath)")
    print("• Coppersmith")
    print("• Факторизация через различные базы данных")
    print("• И многие другие специализированные атаки")

def print_result(M, d, p=None, q=None):
    print("\n" + "=" * 70)
    print("✓✓✓ РАСШИФРОВКА УСПЕШНА! ✓✓✓")
    print("=" * 70)

    if p and q:
        print(f"\np = {p}")
        print(f"q = {q}")

    print(f"\nd (секретный ключ) = {d}")
    print(f"M (расшифрованное) = {M}")

    try:
        hex_str = hex(M)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str

        message_bytes = bytes.fromhex(hex_str)

        for encoding in ['utf-8', 'ascii', 'latin-1']:
            try:
                text = message_bytes.decode(encoding)
                if all(c.isprintable() or c in '\n\r\t' for c in text):
                    print(f"\n📜 Сообщение ({encoding}):")
                    print("=" * 70)
                    print(text)
                    print("=" * 70)
                    return
            except:
                continue

        print(f"\nHex: {hex_str}")
    except Exception as e:
        print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()