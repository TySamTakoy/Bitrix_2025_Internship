import requests
from sympy import mod_inverse

def get_factors_from_factordb(N):
    url = f"http://factordb.com/api?query={N}"
    data = requests.get(url).json()
    factors = data.get("factors", [])
    if len(factors) == 2:
        p = int(factors[0][0])
        q = int(factors[1][0])
        return p, q
    raise ValueError("Не удалось получить разложение N с factordb")

def rsa_decrypt_large(N, E, C):
    p, q = get_factors_from_factordb(N)
    print(f"Найдено разложение:\n p = {p}\n q = {q}")
    phi = (p - 1) * (q - 1)
    D = mod_inverse(E, phi)
    M = pow(C, D, N)
    return M

N = 4543057770210674403041324389667
E = 2**16 + 1
C = 4079647912705989752008920171940

M = rsa_decrypt_large(N, E, C)
print("\nРасшифрованное сообщение (в виде числа):", M)

try:
    print("Сообщение как текст:", bytes.fromhex(hex(M)[2:]).decode())
except Exception:
    print("Сообщение не похоже на текст.")
