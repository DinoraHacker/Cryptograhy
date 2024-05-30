import random
import tkinter as tk
from tkinter import messagebox
from sha512 import sha512


# Функция определения простоты числа, используя алгоримт Миллера-Рабина
def is_prime_miller_rabin(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


# Функция генерации больших простых чисел
def generate_large_prime(bits):
    while True:
        potential_prime = random.getrandbits(bits)
        if is_prime_miller_rabin(potential_prime):
            return potential_prime


# Нахождение НОДа(Наибольшего общего делителя)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# Генерации экспоненты E
def generate_public_exponent(phi_n):
    while True:
        e = random.randint(2, phi_n - 1)
        if gcd(e, phi_n) == 1:
            return e


# Генерация закрытой экспоненты D
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_rsa_keys(bits):
    p = generate_large_prime(bits)
    text_p_display.delete("1.0", tk.END)
    text_p_display.insert("1.0", p)

    q = generate_large_prime(bits)
    text_q_display.delete("1.0", tk.END)
    text_q_display.insert("1.0", q)

    n = p * q
    text_n_display.delete("1.0", tk.END)
    text_n_display.insert("1.0", n)

    phi = (p - 1) * (q - 1)
    text_phi_n_display.delete("1.0", tk.END)
    text_phi_n_display.insert("1.0", phi)

    e = generate_public_exponent(phi)
    text_e_display.delete("1.0", tk.END)
    text_e_display.insert("1.0", e)

    d = mod_inverse(e, phi)
    text_d_display.delete("1.0", tk.END)
    text_d_display.insert("1.0", d)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


# Функция шифрования сообщения
def encrypt(public_key, plaintext):
    n, e = public_key
    encrypted_message = [pow(ord(char), e, n) for char in plaintext]
    return encrypted_message


# Функция расшифровки сообщения
def decrypt(private_key, ciphertext):
    n, d = private_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return decrypted_message


# Функция вывода хэш-значения сообщения и цифровой подписи
def sign(private_key, message):
    n, d = private_key
    hashed_message = int(sha512(message), 16)
    signature = pow(hashed_message, d, n)
    print("hashed_message sign", hashed_message)
    print("signature sign", signature)
    return signature


# Функция проверки цифровой подписи
def verify_signature(public_key, message, signature):
    n, e = public_key
    hashed_message = int(sha512(message), 16)
    verified_message = pow(signature, e, n)
    print("hashed_message verify_signature", hashed_message)
    print("verified_message verify_signature", verified_message)
    return hashed_message == verified_message


def button_click_generate_keys():
    key_length_str = entry_key_length.get("1.0", tk.END).strip()
    try:
        bits = int(key_length_str)
        if (bits < 512):
            messagebox.showerror("Ошибка!", "Минимальное количество бит ключа 512!")
        else:
            public_key, private_key = generate_rsa_keys(bits)
            return public_key, private_key
    except ValueError:
        messagebox.showerror("Ошибка ключа!", "Некорректный ключ! Ключ должен быть целым числом!")


def button_click_encrypt():
    try:
        public_key = (int(text_n_display.get("1.0", tk.END).strip()), int(text_e_display.get("1.0", tk.END).strip()))
        plaintext = entry_plaintext.get("1.0", tk.END).strip()
        ciphertext = encrypt(public_key, plaintext)
        entry_ciphertext.delete("1.0", tk.END)
        entry_ciphertext.insert("1.0", ' '.join(map(str, ciphertext)))
    except ValueError:
        messagebox.showerror("Ошибка ключа!", "Сгенерируйте ключ")


def button_click_decrypt():
    try:
        private_key = (int(text_n_display.get("1.0", tk.END).strip()), int(text_d_display.get("1.0", tk.END).strip()))
        ciphertext = entry_ciphertext.get("1.0", tk.END).strip().split()
        ciphertext = [int(char) for char in ciphertext]
        decrypted_message = decrypt(private_key, ciphertext)
        entry_decrypted_text.delete("1.0", tk.END)
        entry_decrypted_text.insert("1.0", decrypted_message)
    except ValueError:
        messagebox.showerror("Ошибка ключа!", "Сгенерируйте ключ")


def button_click_sign():
    try:
        private_key = (int(text_n_display.get("1.0", tk.END).strip()), int(text_d_display.get("1.0", tk.END).strip()))
        message = entry_plaintext.get("1.0", tk.END).strip()
        signature = sign(private_key, message)
        entry_signature.delete("1.0", tk.END)
        entry_signature.insert("1.0", str(signature))
    except ValueError:
        messagebox.showerror("Ошибка ключа!", "Сгенерируйте ключ")


def button_click_verify():
    try:
        public_key = (int(text_n_display.get("1.0", tk.END).strip()), int(text_e_display.get("1.0", tk.END).strip()))
        message = entry_plaintext.get("1.0", tk.END).strip()
        signature = int(entry_signature.get("1.0", tk.END).strip())
        is_valid = verify_signature(public_key, message, signature)
        entry_verification_result.delete("1.0", tk.END)
        entry_verification_result.insert("1.0", "Подпись действительна" if is_valid else "Подпись недействительна")
    except ValueError:
        messagebox.showerror("Ошибка ключа!", "Сгенерируйте ключ")


root = tk.Tk()
root.title("RSA")

frame_left = tk.Frame(root)
frame_left.pack(side=tk.LEFT, padx=10, pady=10)

frame_right = tk.Frame(root)
frame_right.pack(side=tk.RIGHT, padx=10, pady=10)

# Левая часть - генерация ключей
label_key_length = tk.Label(frame_left, text="Выберите длину ключа:")
label_key_length.pack()
entry_key_length = tk.Text(frame_left, width=10, height=1)
default_key_length = 512
entry_key_length.insert("1.0", default_key_length)
entry_key_length.pack(padx=10)
button_generate_keys = tk.Button(frame_left, text="Сгенерировать ключ", command=button_click_generate_keys, width=20)
button_generate_keys.pack(padx=10)

label_p = tk.Label(frame_left, text="p")
label_p.pack()
text_p_display = tk.Text(frame_left, width=50, height=3)
text_p_display.pack()
label_q = tk.Label(frame_left, text="q")
label_q.pack()
text_q_display = tk.Text(frame_left, width=50, height=3)
text_q_display.pack()
label_n = tk.Label(frame_left, text="N")
label_n.pack()
text_n_display = tk.Text(frame_left, width=50, height=3)
text_n_display.pack()
label_phi_n = tk.Label(frame_left, text="phi(N)")
label_phi_n.pack()
text_phi_n_display = tk.Text(frame_left, width=50, height=3)
text_phi_n_display.pack()
label_e = tk.Label(frame_left, text="e")
label_e.pack()
text_e_display = tk.Text(frame_left, width=50, height=3)
text_e_display.pack()
label_d = tk.Label(frame_left, text="d")
label_d.pack()
text_d_display = tk.Text(frame_left, width=50, height=3)
text_d_display.pack()

# Правая часть - шифрование, дешифрование, подпись, проверка подписи
label_plaintext = tk.Label(frame_right, text="Текст для шифрования:")
label_plaintext.pack()
entry_plaintext = tk.Text(frame_right, height=3, width=50)
entry_plaintext.pack(padx=10)

button_encrypt = tk.Button(frame_right, text="Зашифровать", command=button_click_encrypt, width=57)
button_encrypt.pack(padx=10)

label_ciphertext = tk.Label(frame_right, text="Зашифрованный текст:")
label_ciphertext.pack()
entry_ciphertext = tk.Text(frame_right, height=3, width=50)
entry_ciphertext.pack(padx=10)

button_decrypt = tk.Button(frame_right, text="Расшифровать", command=button_click_decrypt, width=57)
button_decrypt.pack(padx=10)

label_decrypted_text = tk.Label(frame_right, text="Дешифрованный текст:")
label_decrypted_text.pack()
entry_decrypted_text = tk.Text(frame_right, height=3, width=50)
entry_decrypted_text.pack(padx=10)

button_sign = tk.Button(frame_right, text="Подписать", command=button_click_sign, width=57)
button_sign.pack(padx=10)

label_signature = tk.Label(frame_right, text="Подпись:")
label_signature.pack()
entry_signature = tk.Text(frame_right, height=3, width=50)
entry_signature.pack(padx=10)

label_verification_result = tk.Label(frame_right, text="Результат проверки подписи:")
label_verification_result.pack()
entry_verification_result = tk.Text(frame_right, height=1, width=50)
entry_verification_result.pack(padx=10)

button_verify = tk.Button(frame_right, text="Проверить подпись", command=button_click_verify, width=57)
button_verify.pack(padx=10)

root.mainloop()
