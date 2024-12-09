import requests
import json

# URL для отправки запросов
url = "http://localhost:8000"

# Примеры данных для отправки
requests_data = [
    {
        "algorithm": "AES",
        "key": "1234567890abcdef1234567890abcdef",
        "data": "Hello, world!",
        "mode": "CBC",
        "iv": "0000000000000000",
        "key_length": 128
    },
    {
        "algorithm": "3DES",
        "key": "0123456789abcdef0123456789abcdef",
        "data": "Sensitive Data",
        "mode": "CBC",
        "iv": "1111111111111111",
        "key_length": 112
    },
    {
        "algorithm": "RSA",
        "key": "-----BEGIN PUBLIC KEY-----\n...",
        "data": "Important Message",
        "mode": "N/A",
        "iv": None,
        "key_length": 2048
    },
    {
        "algorithm": "ChaCha20",
        "key": "00112233445566778899aabbccddeeff",
        "data": "Confidential Text",
        "mode": "Stream",
        "iv": "1122334455667788",
        "key_length": 256
    },
    {
        "algorithm": "Blowfish",
        "key": "abcdefgh",
        "data": "Private Data",
        "mode": "CFB",
        "iv": "00000000",
        "key_length": 128
    },
    {
        "algorithm": "SHA-256",
        "key": "unused",
        "data": "Hash this data",
        "mode": "N/A",
        "iv": None,
        "key_length": 256
    },
    {
        "algorithm": "DES",
        "key": "abcdef123456",
        "data": "Legacy Data",
        "mode": "ECB",
        "iv": None,
        "key_length": 56
    },
    {
        "algorithm": "ECC",
        "key": "04c0a5e0...",
        "data": "Secure Message",
        "mode": "N/A",
        "iv": None,
        "key_length": 256
    },
    {
        "algorithm": "Twofish",
        "key": "0123456789abcdef0123456789abcdef",
        "data": "Classified",
        "mode": "CBC",
        "iv": "0101010101010101",
        "key_length": 256
    },
    {
        "algorithm": "Camellia",
        "key": "abcdefabcdefabcdefabcdefabcdefab",
        "data": "Confidential Info",
        "mode": "OFB",
        "iv": "1234567890abcdef",
        "key_length": 256
    },
]

# Отправка запросов
for i, data in enumerate(requests_data, start=1):
    response = requests.post(url, json=data)
    print(f"Запрос {i}: Статус {response.status_code}, Ответ: {response.text}")
