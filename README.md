# EntropyVault
Auditable password generator using CSPRNG, HKDF-SHA512, scrypt hardening, entropy estimation and unbiased character selection.
# LeafReader Secure Password Generator

## 🇬🇧 English

A transparent and auditable high-security password generator written in Python.

The project focuses on modern cryptographic practices, secure random number generation, memory-hard key derivation, and unbiased password construction.

Unlike many password generators that simply select random characters, LeafReader combines multiple security mechanisms while remaining open for inspection and independent verification.

### Features

* Cryptographically secure randomness (`secrets`)
* HKDF-SHA512 entropy expansion
* Optional memory-hard strengthening via `scrypt`
* Rejection sampling (eliminates modulo bias)
* Strict password policy validation
* Entropy estimation
* Password strength assessment
* Experimental BB84-style entropy diversification simulation
* Bilingual GUI (English / Russian)
* Fully offline operation
* Open-source and auditable design

### Security Notes

This software does **not** claim absolute security.

Password strength depends on multiple factors:

* Password length
* Character diversity
* Storage security
* Device security
* User practices

The included BB84 simulation is a software-based entropy diversification mechanism and **is not a real quantum key distribution implementation**.

### Requirements

* Python 3.10+
* Tkinter

### Run

```bash
python main.py
```

### Cryptographic Components

| Component          | Purpose                       |
| ------------------ | ----------------------------- |
| secrets            | CSPRNG randomness             |
| HKDF-SHA512        | Entropy expansion             |
| scrypt             | Memory-hard strengthening     |
| SHA-256            | Internal derivations          |
| Rejection Sampling | Bias-free character selection |

### License

MIT License

---

## 🇷🇺 Русский

Прозрачный и проверяемый генератор безопасных паролей на Python.

Проект ориентирован на современные криптографические практики, безопасную генерацию случайности, memory-hard усиление ключевого материала и построение паролей без статистических перекосов.

В отличие от многих генераторов, которые просто выбирают случайные символы, EntropyVault сочетает несколько механизмов защиты и остаётся полностью открытым для анализа и независимой проверки.

### Возможности

* Криптографически стойкая случайность (`secrets`)
* Расширение энтропии через HKDF-SHA512
* Опциональное усиление через `scrypt`
* Rejection Sampling без modulo bias
* Строгая проверка политики паролей
* Оценка энтропии
* Оценка стойкости пароля
* Экспериментальный BB84-подобный механизм диверсификации энтропии
* Двуязычный интерфейс (русский / английский)
* Полностью автономная работа
* Открытый и проверяемый исходный код

### Важное замечание

Программа не заявляет об абсолютной неуязвимости.

Реальная стойкость зависит от:

* длины пароля;
* используемых наборов символов;
* безопасности устройства;
* способа хранения пароля;
* действий пользователя.

Режим BB84 является программной симуляцией и не представляет собой реализацию настоящего квантового распределения ключей.

### Требования

* Python 3.10+
* Tkinter

### Запуск

```bash
python main.py
```

### Используемые криптографические механизмы

| Компонент          | Назначение                                  |
| ------------------ | ------------------------------------------- |
| secrets            | Криптографическая случайность               |
| HKDF-SHA512        | Расширение энтропии                         |
| scrypt             | Memory-hard усиление                        |
| SHA-256            | Внутренние вычисления                       |
| Rejection Sampling | Выбор символов без статистического смещения |

### Лицензия

MIT License
