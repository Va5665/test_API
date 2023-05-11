import pytest
import json
from json import JSONDecodeError
import requests
from unittest.mock import MagicMock, patch
BASE_URL = 'https://api.b2b.tdx.by/'
token = "fMqwsGIt3QewSYAhfguoxa7ecSsU87kZY4KPXKMQGhpx1lQ5qFUCi68dozns5pEi"
token_bad = ""
password = "Ms5r&jdSg"
username = "petrychcho@mediatech.dev"
email = "petrychcho@mediatech.dev"


"""api_v1_auth_captcha_read"""
def test_auth_captcha_read_403():
    url = f'{BASE_URL}api/v1/auth/captcha'
    headers = {
        "accept": "application/json",
        "X-CSRFToken": token
    }


#     response = requests.get(url, headers=headers)
#     print("Response body:", response.text)
#     data = response.json()
#     assert response.status_code == 403
#     assert data["status"] == "string", "Ответ не содержит статуса 'string"
#     assert data["details"] == "string", "Ответ не содержит статуса 'string"


"""api_v1_auth_confirm"""
"""Этот тест не трограем"""
# def test_auth_confirm_404():
#     url = f'{BASE_URL}api/v1/auth/confirm/{token}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#     # Создаем заглушку для запроса
#     response_mock = MagicMock()
#     response_mock.status_code = 200
#     response_mock.json.return_value = {"username": "string", "password": "string"}
#     # Используем заглушку вместо реального запроса
#     with patch("requests.get", return_value=response_mock):
#         response = requests.get(url, headers=headers)
#         assert response.status_code == 200, f"Непредвиденный код ответа: {response.status_code}"
#         print("Test successful : API = 200")
#
#     # response = requests.get(url, headers=headers, json=data)
#     # print("Response body:", response.text)
#     # assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"
#     assert data["status"] == "string", "Ответ не содержит статуса 'string"
#     assert data["details"] == "string", "Ответ не содержит статуса 'string"
#
#     print("Test successful : API 200")
#
#     assert response.status_code == 404, f"Ожидается код 404, получен {response.status_code}"
#     print("Test successful : API = 404")
#
#
#     try:
#         data = response.json()
#         if data is not None:
#             assert  "username" in data, "Ответ не содержит поля 'username' "
#             assert  "password" in data, "Ответ не содержит поля 'password'"
#     except JSONDecodeError:
#         print("Ответ сервера не является корректным JSON")
#
#
#
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": 'GET, POST, OPTIONS, DELETE, HEAD',
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range'
# ,       "allow": "GET, HEAD, OPTIONS",
#
#         "content-type": "text/html; charset=utf-8",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert response.headers[header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")
#
#
