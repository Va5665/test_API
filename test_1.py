import requests
import json
BASE_URL = 'https://api.b2b.tdx.by/'
token = "1eXop0n9FOOQmO6nkqkzEEIGmqb7PvFjKwhHU4rwifZRvbmbvPKNpAJFy76FMNZC"
token_bad = "8768oyfgit76"
password = "Ms5r&jdSg"
username = "petrychcho@mediatech.dev"
email = "petrychcho@mediatech.dev"

class APITest:
    def __init__(self):
        self.base_url = BASE_URL
        self.token = token
        self.username = username
        self.password = password
        self.token_bad = token_bad
        self.expected_headers_get = {
            "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
            "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
            "access-control-allow-origin": "*",
            "access-control-expose-headers": "Content-Disposition, Content-Length,Content-Range",
            "allow": "GET, HEAD, OPTIONS",
            "content-type": "application/json",
            "referrer-policy": "same-origin",
            "server": "nginx",
            "vary": "Accept",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY"
        }

        self.expected_headers_post = {
            "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
            "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
            "access-control-allow-origin": "*",
            "access-control-expose-headers": "Content-Disposition, Content-Length,Content-Range",
            "allow": "POST, OPTIONS",
            "content-type": "application/json",
            "referrer-policy": "same-origin",
            "server": "nginx",
            "vary": "Accept",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY"
        }
api_test = APITest()

def check_headers(expected_headers, response_headers):
    for header, value in expected_headers.items():
        assert header in response_headers, f"Отсутствует заголовок: {header}"
        assert response_headers[header] == value, f"Неверное значение для заголовка '{header}': ожидалось '{value}', получено '{response_headers[header]}'"
def test_auth_captcha_read():
    url = f'{BASE_URL}api/v1/auth/captcha'
    headers = {
        "accept": "application/json",
        "X-CSRFToken": token
    }
    response = requests.get(url, headers=headers)
    print("Response body:", response.text)
    print(f"Response status code (correct token): {response.status_code}")
    assert response.status_code == 200, f"Непредвиденный код ответа: {response.status_code}"
    print("Test successful : API = 200")
    data = response.json()
    assert "id" in data, "0"
    assert isinstance(data["id"], int), "Поле 'id' имеет некорректный тип данных"
    assert data["id"] > 0, "Поле 'id' имеет некорректное значение"
    assert data["image"].startswith(
        "https://media.b2b.tdx.by/captcha/captcha-"), "Поле 'image' имеет некорректное значение"
    print("Тест пройден: ответ содержит корректные поля 'id' и 'image'")

    check_headers(api_test.expected_headers_get, response.headers)


    run_test(api_test, token)
    incorrect_token = token
    if token != incorrect_token:
        # Запуск теста с некорректным токеном
        test_failed = run_test(incorrect_token)
        assert test_failed, "Тест прошел  удачно с кодом 200," \
                            " НО проходит и с не " \
                            "корректным токеном "

def run_test(self, test_token):
    url = f'{BASE_URL}api/v1/auth/captcha'
    headers = {
        "accept": "application/json",
        "X-CSRFToken": test_token
    }
    response = requests.get(url, headers=headers)
    print(f"Response status code ({test_token}): {response.status_code}")
    if response.status_code == 200 and self.token != self.token:
        return False
    return True


def test_auth_login():
    url = f"{BASE_URL}api/v1/auth/login"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "X-CSRFToken": token
    }
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(url, headers=headers, json=data)
    print("Response body:", response.text)
    assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"
    print("Test successful : API = 200")
    data = json.loads(response.text)
    assert response.status_code == 200
    assert data['status'] == 'Ok'
    assert data['details'] == 'Welcome!'
    assert 'token' in data
    print("Тест пройден: ответ содержит корректные поля")

    data = {
        "username": "string",
        "password": "string"
    }
    response = requests.post(url, headers=headers, json=data)
    print("Response body:", response.text)
    assert response.status_code == 401, f"Ожидается код 401, получен {response.status_code}"
    print("Test NO successful : API = 401")
    data = response.json()
    assert data['status'] == 'Fail'
    assert data['details'] == 'Неверное имя пользователя или пароль'
    assert data['token'] == 'guest'
    check_headers(api_test.expected_headers_post, response.headers)

