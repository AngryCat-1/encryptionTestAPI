import json

from django.http import JsonResponse
from cryptography.hazmat.primitives.ciphers import algorithms as sym_algorithms
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256, SHA512
import math
def check_issues(algorithm, key, data, mode, iv, key_length):
    issues = []

    if algorithm == "DES":
        issues.append({"type": "УстаревшийАлгоритм", "description": "DES слишком слаб для современных атак. Используйте AES."})
        if key_length != 56:
            issues.append({"type": "ОшибкаДлиныКлюча", "description": "DES использует короткий ключ (56 бит), что делает его уязвимым."})

    elif algorithm == "3DES":
        issues.append({"type": "УстаревшийАлгоритм", "description": "3DES устарел и подвержен атакам. Используйте AES."})
        if key_length != 168:
            issues.append({"type": "ОшибкаДлиныКлюча", "description": "3DES использует слабую длину ключа, рекомендуется 168 бит."})

    elif algorithm == "RC4":
        issues.append({"type": "УстаревшийАлгоритм", "description": "RC4 имеет известные уязвимости. Используйте AES или ChaCha20."})

    elif algorithm == "SHA-1":
        issues.append({"type": "УстаревшийАлгоритм", "description": "SHA-1 подвержен атакам на коллизии и не должен использоваться."})

    if algorithm == "AES" and key_length not in [128, 192, 256]:
        issues.append({"type": "ОшибкаДлиныКлюча", "description": f"Для AES рекомендуется использовать ключи длиной 128, 192 или 256 бит. Текущая длина: {key_length}."})

    if algorithm == "RSA" and key_length < 3072:
        issues.append({"type": "ОшибкаДлиныКлюча", "description": "Для RSA рекомендуется использовать ключ длиной не менее 3072 бит."})

    if mode.upper() == "ECB":
        issues.append({"type": "НебезопасныйРежим", "description": "Режим ECB уязвим для атак. Используйте CBC или GCM."})

    if mode.upper() == "GCM" and iv == "0000000000000000":
        issues.append({"type": "ПовторениеIV", "description": "IV статичен. Использование одинаковых IV для разных сообщений уязвимо."})

    if mode.upper() == "CBC" and iv == "0000000000000000":
        issues.append({"type": "ПовторениеIV", "description": "IV статичен. Использование одинаковых IV для разных сообщений уязвимо."})

    if iv == "0000000000000000":
        issues.append({"type": "НеверныйIV", "description": "IV не должен быть статичным (все нули). Используйте случайный или уникальный IV для каждого сообщения."})

    if len(iv) != 16 and (mode.upper() in ["CBC", "GCM"]):
        issues.append({"type": "НевернаяДлинаIV", "description": f"IV для {mode} должен быть длиной 16 байт."})

    if algorithm == "AES" and data == "0000000000000000":
        issues.append({"type": "ПредсказуемыеДанные", "description": "Данные шифруются пустыми или предсказуемыми значениями. Используйте уникальные данные."})

    # 6. Уязвимости в использовании с ключами
    if algorithm == "RSA" and len(key) < 2048:
        issues.append({"type": "УязвимостьКлюча", "description": "RSA с ключом менее 2048 бит уязвим к атаке на факторизацию."})

    if algorithm == "ECC" and key_length < 256:
        issues.append({"type": "ОшибкаДлиныКлюча", "description": "Для ECC рекомендуется использовать ключ длиной не менее 256 бит."})

    if algorithm == "SHA-1" and data != "0000000000000000":
        issues.append({"type": "УстаревшийАлгоритм", "description": "SHA-1 подвержен атакам на коллизии. Используйте SHA-256 или SHA-512."})

    if algorithm == "AES" and key_length == 128 and mode.upper() == "CBC":
        issues.append({"type": "ПроблемыСПроизводительностью", "description": "Для AES с ключом 128 бит и режимом CBC может быть уменьшена скорость из-за необходимости дополнения."})

    if key == "0000000000000000":
        issues.append({"type": "НеверныйКлюч", "description": "Ключ не должен быть простым или статичным (все нули). Используйте случайные или уникальные ключи."})

    if algorithm in ["AES", "RSA", "ECC"] and iv == "0000000000000000" and key == "0000000000000000":
        issues.append({"type": "ПроблемыСБезопасностьюБиблиотек", "description": "Использование простых значений для ключей и IV может привести к уязвимостям в криптографических библиотеках."})

    return issues

def brute_force_time(algorithm, key_length, attempts_per_second):
    algorithm_factors = {
        "DES": 2**-56,
        "3DES": 2**-112,
        "RC4": 1.0,
        "SHA-1": 2**-80,
        "SHA-256": 1.0,
        "AES": 1.0,
        "RSA": 2**-1024,
        "ECC": 2**-128,
        "BLOWFISH": 1.0,
        "TWOFISH": 1.0,
        "CHACHA20": 1.0,
        "CAMELLIA": 1.0,
    }

    if algorithm not in algorithm_factors:
        return "-2"

    effective_key_space_factor = algorithm_factors[algorithm]
    key_space = (2 ** key_length) * effective_key_space_factor

    if key_space <= 0:
        return "-1"

    time_seconds = key_space / attempts_per_second
    time_minutes = time_seconds / 60
    time_hours = time_minutes / 60

    return time_hours


def calculate_strength_score(algorithm, key, data, mode, iv, key_length):
    score = 10.0

    algorithm_scores = {
        "DES": 1.0,
        "3DES": 3.0,
        "RC4": 2.0,
        "SHA-1": 2.5,
        "SHA-256": 9.0,
        "AES": 9.5,
        "RSA": 8.5,
        "ECC": 9.0,
        "BLOWFISH": 7.5,
        "TWOFISH": 8.0,
        "CHACHA20": 9.0,
        "CAMELLIA": 8.5,
    }

    if algorithm in algorithm_scores:
        score -= (10 - algorithm_scores[algorithm])

    key_length_risk = 0
    if algorithm == "AES":
        if key_length < 128:
            key_length_risk = 3
        elif key_length == 128:
            key_length_risk = 2
        elif key_length == 192:
            key_length_risk = 1
        elif key_length == 256:
            key_length_risk = 0
    elif algorithm == "RSA":
        if key_length < 2048:
            key_length_risk = 4
        elif key_length == 2048:
            key_length_risk = 2
        elif key_length == 3072:
            key_length_risk = 1
        elif key_length >= 4096:
            key_length_risk = 0
    elif algorithm == "ECC":
        if key_length < 256:
            key_length_risk = 3
        elif key_length == 256:
            key_length_risk = 1
        elif key_length >= 384:
            key_length_risk = 0

    score -= key_length_risk

    mode_risk = 0
    if mode.upper() == "ECB":
        mode_risk = 4
    elif mode.upper() == "CBC":
        mode_risk = 2
    elif mode.upper() == "GCM":
        mode_risk = 0
    elif mode.upper() == "CFB":
        mode_risk = 1
    elif mode.upper() == "OFB":
        mode_risk = 1
    elif mode.upper() == "CTR":
        mode_risk = 1

    score -= mode_risk

    iv_risk = 0
    if iv == "0000000000000000" or iv == "FFFFFFFFFFFFFFFF":
        iv_risk = 3
    elif iv is None or len(iv) != 16:
        iv_risk = 2

    score -= iv_risk

    brute_force_risk = 0
    known_plaintext_risk = 0

    if algorithm == "AES":
        if key_length == 128:
            brute_force_risk = 2
        elif key_length == 256:
            brute_force_risk = 0

    if data == "0000000000000000":
        known_plaintext_risk = 3
    elif data == "deadbeefdeadbeef":
        known_plaintext_risk = 2

    score -= brute_force_risk + known_plaintext_risk

    key_risk = 0
    if key == "0000000000000000":
        key_risk = 5
    elif len(key) < key_length // 8:
        key_risk = 3

    score -= key_risk

    data_risk = 0
    if data == "0000000000000000":
        data_risk = 2

    score -= data_risk

    score = max(0, min(score, 10))

    return round(score, 1)

def security_rating(time_years):
    if time_years >= 10**20:
        return "Абсолютно надёжный (практически невозможно взломать)"
    elif time_years >= 10**15:
        return "Криптографически устойчивый (взлом займёт миллиарды лет)"
    elif time_years >= 10**10:
        return "Высокий уровень защиты (взлом займёт десятки миллионов лет)"
    elif time_years >= 10**5:
        return "Средний уровень защиты (взлом займёт сотни тысяч лет)"
    elif time_years >= 1:
        return "Низкий уровень защиты (взлом займёт годы)"
    elif time_years >= 1 / 365.25:
        return "Уязвимый (взлом займёт месяцы или недели)"
    elif time_years >= 1 / (365.25 * 24):
        return "Очень уязвимый (взлом займёт часы или дни)"
    else:
        return "Практически незащищённый (взлом занимает минуты или мгновенно)"

def index(request):
    json_req = json.loads(request.body)
    algorithm = json_req.get('algorithm', '').upper()

    available_algorithms = {
            "symmetric": ["CHACHA20","AES128", "AES"],
            "asymmetric": ["RSA", "ECDSA", "ED25519", "ED448"],
            "hash": ["SHA256", "SHA512", "SHA3_256", "SHA3_512"]
        }

    if not any(algorithm in algos for algos in available_algorithms.values()):
        #return JsonResponse({"status": "error", "message": f"Алоритм'{algorithm}' не поддерживается или его не существует."})
        pass

    if json_req.get('iv', None) == None:
        return JsonResponse({"status": "error", "message": "Некорректный IV параметр"})

    issues = check_issues(algorithm, json_req.get('key', ''), json_req.get('data', ''), json_req.get('mode', ''), json_req.get('iv', ''), json_req.get('key_length', ''))
    strength_score = calculate_strength_score(algorithm, json_req.get('key', ''), json_req.get('data', ''), json_req.get('mode', ''), json_req.get('iv', ''), json_req.get('key_length', ''))
    brute_force_count_sec = 1000000000
    brute_force_time_var = int(brute_force_time(algorithm,  json_req.get('key_length', ''), brute_force_count_sec))

    if (brute_force_time_var == -1):
         return JsonResponse({"status": "error", "message": f"Неизвестный алгоритм: {algorithm}"})
    elif (brute_force_time_var == -2):
        return JsonResponse({"status": "error", "message": "Пространство ключей не может быть нулевым или отрицательным"})

    brute_force_security_strong = security_rating(brute_force_time_var / 8760)

    answer = {
        'info' :
                  {
                    "algorithm" : algorithm,
                    'key' : json_req.get('key', ''),
                    'data' : json_req.get('data', ''),
                    "mode" : json_req.get('mode', ''),
                    'iv' : json_req.get('iv', ''),
                    'key_length' : json_req.get('key_length', '')
                  },
        "strength_score" : strength_score,
        'bruteforce' :
            {
                'time_years' : brute_force_time_var,
                'security_strong' : brute_force_security_strong
            },
        'issues' : issues

        }


    #if request.body['algorithm']
    return JsonResponse(answer)
