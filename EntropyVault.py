#!/usr/bin/env python3
"""Auditable high-security password generator with bilingual GUI (RU/EN).

Security principles:
- CSPRNG-only randomness via `secrets`
- HKDF-SHA512 for entropy expansion
- optional memory-hard hardening with scrypt
- rejection sampling (no modulo bias)
- strict policy validation and bounded parameters
- transparent security messaging (no absolute-security claims)
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import string
import threading
import tkinter as tk
from dataclasses import dataclass
from hashlib import sha512
from tkinter import messagebox, ttk

ALLOWED_SYMBOLS = "!@#$%^&*.()"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 512
DEFAULT_SCRYPT_N = 2**14


def _unique_alphabet(*parts: str) -> str:
    seen: set[str] = set()
    result: list[str] = []
    for part in parts:
        for ch in part:
            if ch not in seen:
                seen.add(ch)
                result.append(ch)
    return "".join(result)


DEFAULT_ALPHABET = _unique_alphabet(string.ascii_letters, string.digits, ALLOWED_SYMBOLS)


@dataclass(frozen=True)
class PasswordPolicy:
    length: int = 32
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True

    def required_sets(self) -> list[str]:
        sets: list[str] = []
        if self.require_lower:
            sets.append(string.ascii_lowercase)
        if self.require_upper:
            sets.append(string.ascii_uppercase)
        if self.require_digit:
            sets.append(string.digits)
        if self.require_symbol:
            sets.append(ALLOWED_SYMBOLS)
        return sets

    def validate(self, alphabet: str) -> None:
        if not isinstance(self.length, int):
            raise ValueError("Password length must be an integer")
        if self.length < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password length must be at least {MIN_PASSWORD_LENGTH}")
        if self.length > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password length must be <= {MAX_PASSWORD_LENGTH}")
        if not alphabet:
            raise ValueError("Alphabet must not be empty")

        required = self.required_sets()
        if not required:
            raise ValueError("Enable at least one character class")
        if self.length < len(required):
            raise ValueError("Password length is too small for required classes")


def _random_bit_list(length: int) -> list[int]:
    if length <= 0:
        raise ValueError("Length must be positive")
    value = secrets.randbits(length)
    return [(value >> i) & 1 for i in range(length)]


def simulate_bb84_key(length: int = 1024) -> str:
    """BB84-style software sifting simulation.

    This is entropy diversification only, not physical QKD.
    """
    if length <= 0:
        raise ValueError("Length must be positive")

    out: list[str] = []
    while len(out) < length:
        batch = min(1024, length - len(out))
        sender_bits = _random_bit_list(batch)
        sender_basis = _random_bit_list(batch)
        receiver_basis = _random_bit_list(batch)
        for idx in range(batch):
            if sender_basis[idx] == receiver_basis[idx]:
                out.append(str(sender_bits[idx]))
    return "".join(out[:length])


def generate_csprng_bits(length: int = 1024) -> str:
    if length <= 0:
        raise ValueError("Length must be positive")
    return format(secrets.randbits(length), f"0{length}b")


def _bits_to_bytes(bits: str) -> bytes:
    if not bits:
        raise ValueError("Bit string must not be empty")
    padded_len = math.ceil(len(bits) / 8) * 8
    integer = int(bits.ljust(padded_len, "0"), 2)
    return integer.to_bytes(padded_len // 8, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, sha512).digest()


def _hkdf_expand(prk: bytes, info: bytes, out_len: int) -> bytes:
    if out_len <= 0:
        raise ValueError("HKDF output length must be positive")
    if out_len > 255 * sha512().digest_size:
        raise ValueError("HKDF output length exceeds RFC 5869 limits")

    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < out_len:
        prev = hmac.new(prk, prev + info + bytes([counter]), sha512).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:out_len])


def derive_entropy(master_bits: str, context: bytes, out_len: int, pepper: bytes) -> bytes:
    if not context:
        raise ValueError("Context is required")
    if not pepper:
        raise ValueError("Pepper is required")

    extra_entropy = secrets.token_bytes(64)
    ikm = _bits_to_bytes(master_bits) + extra_entropy + pepper
    salt = hashlib.sha256(context + pepper + b"/leafreader-hkdf-salt-v3").digest()
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, b"leafreader/passwords/hkdf-v3/" + context, out_len)


def _rejection_sample(alphabet: str, count: int, seed: bytes) -> list[str]:
    if not alphabet:
        raise ValueError("Alphabet must not be empty")
    if count <= 0:
        raise ValueError("Count must be positive")

    out: list[str] = []
    limit = 256 - (256 % len(alphabet))
    pool = seed
    idx = 0

    while len(out) < count:
        if idx >= len(pool):
            pool = hashlib.sha512(pool + secrets.token_bytes(32)).digest()
            idx = 0
        val = pool[idx]
        idx += 1
        if val < limit:
            out.append(alphabet[val % len(alphabet)])

    return out


def _estimate_entropy_bits(alphabet: str, length: int, required_sets: list[str]) -> float:
    if not required_sets:
        return length * math.log2(len(alphabet))

    remaining = length - len(required_sets)
    if remaining < 0:
        raise ValueError("Length too small for required classes")

    combinations = math.comb(length, len(required_sets))
    mandatory_space = math.prod(len(s) for s in required_sets)
    free_space = len(alphabet) ** remaining
    return math.log2(combinations * mandatory_space * free_space)


def _strength_label(entropy_bits: float, lang: str) -> str:
    if entropy_bits < 70:
        return "Низкая" if lang == "ru" else "Low"
    if entropy_bits < 100:
        return "Средняя" if lang == "ru" else "Medium"
    if entropy_bits < 140:
        return "Высокая" if lang == "ru" else "High"
    return "Очень высокая" if lang == "ru" else "Very high"


def generate_strong_password(
    policy: PasswordPolicy,
    alphabet: str = DEFAULT_ALPHABET,
    use_bb84_mix: bool = False,
    use_scrypt: bool = True,
    scrypt_n: int = DEFAULT_SCRYPT_N,
) -> tuple[str, float]:
    policy.validate(alphabet)
    required = policy.required_sets()

    bits = generate_csprng_bits(1024)
    if use_bb84_mix:
        bb84_bits = simulate_bb84_key(1024)
        mixed = int(bits, 2) ^ int(bb84_bits, 2)
        bits = format(mixed, "01024b")

    pepper = secrets.token_bytes(32)
    context = secrets.token_bytes(16)
    key = derive_entropy(bits, context=context, out_len=128, pepper=pepper)

    if use_scrypt:
        if scrypt_n < 2 or scrypt_n & (scrypt_n - 1):
            raise ValueError("scrypt_n must be a power of two >= 2")
        key = hashlib.scrypt(
            password=key,
            salt=hashlib.sha256(context + pepper + b"/scrypt").digest(),
            n=scrypt_n,
            r=8,
            p=1,
            dklen=128,
        )

    password_chars = _rejection_sample(alphabet, policy.length, key)
    for idx, charset in enumerate(required):
        password_chars[idx] = _rejection_sample(charset, 1, secrets.token_bytes(32))[0]
    secrets.SystemRandom().shuffle(password_chars)

    entropy = _estimate_entropy_bits(alphabet, policy.length, required)
    return "".join(password_chars), entropy


I18N = {
    "ru": {
        "title": "Генератор безопасных паролей",
        "length": "Длина",
        "lower": "Строчные",
        "upper": "Заглавные",
        "digit": "Цифры",
        "symbol": "Символы",
        "bb84": "BB84-микс (экспериментально)",
        "scrypt": "Scrypt-усиление",
        "generate": "Сгенерировать",
        "copy": "Копировать",
        "lang": "Switch to English",
        "entropy": "Энтропия",
        "strength": "Стойкость",
        "copied": "Пароль скопирован в буфер обмена",
        "busy": "Генерация...",
        "ready": "Готово",
        "error": "Ошибка",
        "note": "Важно: абсолютной неуязвимости не бывает; стойкость зависит от длины, политики и защиты хранилища.",
    },
    "en": {
        "title": "Secure Password Generator",
        "length": "Length",
        "lower": "Lowercase",
        "upper": "Uppercase",
        "digit": "Digits",
        "symbol": "Symbols",
        "bb84": "BB84 mix (experimental)",
        "scrypt": "Scrypt hardening",
        "generate": "Generate",
        "copy": "Copy",
        "lang": "Переключить на русский",
        "entropy": "Entropy",
        "strength": "Strength",
        "copied": "Password copied to clipboard",
        "busy": "Generating...",
        "ready": "Ready",
        "error": "Error",
        "note": "Important: no absolute immunity exists; strength depends on length, policy, and storage-side defenses.",
    },
}


class PasswordGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.lang = "ru"
        self.root.geometry("740x430")
        self.root.minsize(700, 420)

        self.length_var = tk.IntVar(value=32)
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)
        self.bb84_var = tk.BooleanVar(value=False)
        self.scrypt_var = tk.BooleanVar(value=True)

        self.password_var = tk.StringVar()
        self.entropy_var = tk.StringVar()
        self.strength_var = tk.StringVar()
        self.status_var = tk.StringVar()

        self._build_ui()
        self._apply_i18n()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=14)
        frame.pack(fill=tk.BOTH, expand=True)

        self.title_label = ttk.Label(frame, font=("Arial", 15, "bold"))
        self.title_label.pack(anchor=tk.W, pady=(0, 10))

        row = ttk.Frame(frame)
        row.pack(fill=tk.X)
        self.length_label = ttk.Label(row)
        self.length_label.pack(side=tk.LEFT)
        ttk.Spinbox(row, from_=MIN_PASSWORD_LENGTH, to=MAX_PASSWORD_LENGTH, textvariable=self.length_var, width=8).pack(side=tk.LEFT, padx=8)

        checks = ttk.Frame(frame)
        checks.pack(fill=tk.X, pady=8)
        self.cb_lower = ttk.Checkbutton(checks, variable=self.lower_var)
        self.cb_upper = ttk.Checkbutton(checks, variable=self.upper_var)
        self.cb_digit = ttk.Checkbutton(checks, variable=self.digit_var)
        self.cb_symbol = ttk.Checkbutton(checks, variable=self.symbol_var)
        self.cb_bb84 = ttk.Checkbutton(checks, variable=self.bb84_var)
        self.cb_scrypt = ttk.Checkbutton(checks, variable=self.scrypt_var)

        self.cb_lower.grid(row=0, column=0, sticky=tk.W, padx=(0, 12))
        self.cb_upper.grid(row=0, column=1, sticky=tk.W, padx=(0, 12))
        self.cb_digit.grid(row=0, column=2, sticky=tk.W, padx=(0, 12))
        self.cb_symbol.grid(row=0, column=3, sticky=tk.W)
        self.cb_bb84.grid(row=1, column=0, sticky=tk.W, pady=(4, 0), padx=(0, 12))
        self.cb_scrypt.grid(row=1, column=1, sticky=tk.W, pady=(4, 0))

        controls = ttk.Frame(frame)
        controls.pack(fill=tk.X, pady=(8, 8))
        self.generate_btn = ttk.Button(controls, command=self.generate_async)
        self.generate_btn.pack(side=tk.LEFT)
        self.copy_btn = ttk.Button(controls, command=self.copy_password)
        self.copy_btn.pack(side=tk.LEFT, padx=8)
        self.lang_btn = ttk.Button(controls, command=self.toggle_language)
        self.lang_btn.pack(side=tk.RIGHT)

        ttk.Entry(frame, textvariable=self.password_var, font=("Consolas", 12)).pack(fill=tk.X, pady=(0, 8))
        ttk.Label(frame, textvariable=self.entropy_var).pack(anchor=tk.W)
        ttk.Label(frame, textvariable=self.strength_var).pack(anchor=tk.W)

        self.note_label = ttk.Label(frame, foreground="#555555", wraplength=700)
        self.note_label.pack(anchor=tk.W, pady=(8, 4))

        ttk.Separator(frame).pack(fill=tk.X, pady=(4, 4))
        ttk.Label(frame, textvariable=self.status_var).pack(anchor=tk.W)

    def _apply_i18n(self) -> None:
        t = I18N[self.lang]
        self.root.title(t["title"])
        self.title_label.configure(text=t["title"])
        self.length_label.configure(text=t["length"] + ":")
        self.cb_lower.configure(text=t["lower"])
        self.cb_upper.configure(text=t["upper"])
        self.cb_digit.configure(text=t["digit"])
        self.cb_symbol.configure(text=t["symbol"])
        self.cb_bb84.configure(text=t["bb84"])
        self.cb_scrypt.configure(text=t["scrypt"])
        self.generate_btn.configure(text=t["generate"])
        self.copy_btn.configure(text=t["copy"])
        self.lang_btn.configure(text=t["lang"])
        self.note_label.configure(text=t["note"])
        if not self.status_var.get():
            self.status_var.set(t["ready"])

    def toggle_language(self) -> None:
        self.lang = "en" if self.lang == "ru" else "ru"
        self._apply_i18n()

    def generate_async(self) -> None:
        self.generate_btn.configure(state=tk.DISABLED)
        self.status_var.set(I18N[self.lang]["busy"])
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self) -> None:
        try:
            policy = PasswordPolicy(
                length=int(self.length_var.get()),
                require_lower=self.lower_var.get(),
                require_upper=self.upper_var.get(),
                require_digit=self.digit_var.get(),
                require_symbol=self.symbol_var.get(),
            )
            password, entropy = generate_strong_password(
                policy=policy,
                use_bb84_mix=self.bb84_var.get(),
                use_scrypt=self.scrypt_var.get(),
            )
            self.root.after(0, self._render_result, password, entropy)
        except Exception as exc:
            self.root.after(0, self._render_error, str(exc))

    def _render_result(self, password: str, entropy: float) -> None:
        t = I18N[self.lang]
        self.password_var.set(password)
        self.entropy_var.set(f"{t['entropy']}: ~{entropy:.1f} bits")
        self.strength_var.set(f"{t['strength']}: {_strength_label(entropy, self.lang)}")
        self.status_var.set(t["ready"])
        self.generate_btn.configure(state=tk.NORMAL)

    def _render_error(self, message: str) -> None:
        self.generate_btn.configure(state=tk.NORMAL)
        self.status_var.set(I18N[self.lang]["ready"])
        messagebox.showerror(I18N[self.lang]["error"], message)

    def copy_password(self) -> None:
        password = self.password_var.get()
        if not password:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("OK", I18N[self.lang]["copied"])


def main() -> None:
    root = tk.Tk()
    PasswordGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
