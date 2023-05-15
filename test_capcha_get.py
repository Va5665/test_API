
import requests
from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest
import json
from json import JSONDecodeError
BASE_URL = 'https://api.b2b.tdx.by/'
token = "1eXop0n9FOOQmO6nkqkzEEIGmqb7PvFjKwhHU4rwifZRvbmbvPKNpAJFy76FMNZC"
token_bad = "8768oyfgit76"
password = "Ms5r&jdSg"
username = "petrychcho@mediatech.dev"
email = "petrychcho@mediatech.dev"

# ----------------------------------------------------------------------------
"""api_v1_auth_captcha_read
В этом тесте при не корректном токине, так же приходит ответ 200. 
Если это нормально, то строку 'incorrect_token = token_bad' 
надо поменять на 'incorrect_token = token' """

# def test_auth_captcha_read():
#     url = f'{BASE_URL}api/v1/auth/captcha'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     print("Response body:", response.text)
#     print(f"Response status code (correct token): {response.status_code}")
#     assert response.status_code == 200, f"Непредвиденный код ответа: {response.status_code}"
#     print("Test successful : API = 200")
#     data = response.json()
#     assert "id" in data, "0"
#     assert isinstance(data["id"], int), "Поле 'id' имеет некорректный тип данных"
#     assert data["id"] > 0, "Поле 'id' имеет некорректное значение"
#     assert data["image"].startswith(
#         "https://media.b2b.tdx.by/captcha/captcha-"), "Поле 'image' имеет некорректное значение"
#     print("Тест пройден: ответ содержит корректные поля 'id' и 'image'")
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": 'GET, POST, OPTIONS, DELETE, HEAD',
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range'
#         ,
#         "allow": "GET, HEAD, OPTIONS",
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert response.headers[
#                    header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")
#     run_test(token)
#     incorrect_token = token
#     if token != incorrect_token:
#         # Запуск теста с некорректным токеном
#         test_failed = run_test(incorrect_token)
#         assert test_failed, "Тест прошел  удачно с кодом 200," \
#                             " НО проходит и с не " \
#                             "корректным токеном "
#
# def run_test(test_token):
#     url = f'{BASE_URL}api/v1/auth/captcha'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": test_token
#     }
#     response = requests.get(url, headers=headers)
#     print(f"Response status code ({test_token}): {response.status_code}")
#     if response.status_code == 200 and test_token != token:
#         return False
#     return True
# --------------------------------------------------------------------------------------



""" Ты сказал его не трогаем, этот тест """

"""def test_auth_password"""
# def test_auth_password():
#         url = f'{BASE_URL}api/v1/auth/change'
#         headers = {
#             "accept": 'application/json',
#             "Content-Type": "application/json",
#             "X-CSRFToken": token
#         }
#
#         data = {"old": oldPassword,
#                 "new": newPassword
#                 }
#         response = requests.post(url, headers=headers, json=data)
#
#         assert response.status_code == 401
#         response_data = response.json()
#         print(f"Response status code: {response.status_code}")
#         assert response_data['status'] == 'Fail'
#         assert response_data['details'] == 'Unauthorized'
#         print("Тест пройден: ответ содержит корректный код 401 и корректное содержание")
#
#         assert response.status_code == 403
#         response_data = response.json()
#         print(f"Response status code: {response.status_code}")
#         assert response_data['status'] == 'Fail'
#         assert response_data['details'] == 'Неверный пароль'
#         print("Тест пройден: ответ содержит корректный код 404 и корректное содержание")
#         assert response.status_code == 200
#         print("Test successful : API = 200")
#         data = response.json()
#         print(f"Response status code: {response.status_code}")
#         assert data["id"] == "integer", "Ответ не содержит статуса 'integer"
#         assert data["is_active"] == "boolean", "Ответ не содержит статуса 'boolean"
#         assert data["name"] == "string", "Ответ не содержит статуса 'string"
#         assert data["phone"] == "string", "Ответ не содержит статуса 'string"
#         assert data["email"] == "string", "Ответ не содержит статуса 'string"
#
#         expected_headers = {
#             "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#             "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#             "access-control-allow-origin": "*",
#             "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#             "allow": 'POST, OPTIONS',
#             "content-type": "application/json",
#             "referrer-policy": "same-origin",
#             "server": "nginx",
#             "vary": "Accept",
#             "x-content-type-options": "nosniff",
#             "x-frame-options": "DENY"
#         }
#         for header, expected_value in expected_headers.items():
#             assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#             assert response.headers[
#                        header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#         print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")


"""def test_auth_confirm_200
           ты сказал его  не трогаем"""

# def test_auth_confirm():
#     url = f'{BASE_URL}api/v1/auth/confirm/{token}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token

#     # response = requests.get(url, headers=headers)
#     # data = response.json()
#     #
#     # assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"
#     # assert data["username"] == "string", "Ответ не содержит статуса 'string"
#     # assert data["password"] == "string", "Ответ не содержит статуса 'string"
#     #
#     # print("Test successful : API 200")
#




"""api_v1_auth_login"""

# def test_auth_login():
#     url = f"{BASE_URL}api/v1/auth/login"
#     headers = {
#         "accept": "application/json",
#         "Content-Type": "application/json",
#         "X-CSRFToken": token
#     }
#     data = {
#         "username": username,
#         "password": password
#     }
#     response = requests.post(url, headers=headers, json=data)
#     print("Response body:", response.text)
#     assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"
#     print("Test successful : API = 200")
#     data = json.loads(response.text)
#     assert response.status_code == 200
#     assert data['status'] == 'Ok'
#     assert data['details'] == 'Welcome!'
#     assert 'token' in data
#     print("Тест пройден: ответ содержит корректные поля")
#
#     data = {
#         "username": "string",
#         "password": "string"
#     }
#     response = requests.post(url, headers=headers, json=data)
#     print("Response body:", response.text)
#     assert response.status_code == 401, f"Ожидается код 401, получен {response.status_code}"
#     print("Test NO successful : API = 401")
#     data = response.json()
#     assert data['status'] == 'Fail'
#     assert data['details'] == 'Неверное имя пользователя или пароль'
#     assert data['token'] == 'guest'
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'POST, OPTIONS',
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert  response.headers[header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")
#





"""Как получить 200?"""
# def test_auth_payments():
#     url = f'{BASE_URL}api/v1/auth/payments'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
    # assert response.status_code == 404
    # print("Test successful : API = 404")
    # data = response.json()
    # assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
    # assert data["details"] == "Не найден контрагент", "Ответ не содержит информации 'Не найден контрагент'"
    # print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
    # assert response.status_code == 403
    # print("Test successful : API = 403")
    # data = response.json()
    # assert "status" in data, "Ответ не содержит ключ 'status'"
    # assert "details" in data, "Ответ не содержит ключ 'details'"
    # print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
    # assert response.status_code == 200
    # print("Test successful : API = 200")
    # data = response.json()
    # assert "id" in data, "Ответ не содержит ключ 'id'"
    # assert "sum" in data, "Ответ не содержит ключ 'sum'"
    # assert "type" in data, "Ответ не содержит ключ 'type'"
    # assert "user" in data, "Ответ не содержит ключ 'user'"
    # assert "partner" in data, "Ответ не содержит ключ 'partner'"
    # assert "comment" in data, "Ответ не содержит ключ 'comment'"
    # assert "date" in data, "Ответ не содержит ключ 'date'"
    # print("Тест пройден: ответ содержит корректные поля 'id', 'sum', 'type', 'user', 'partner', 'comment' и 'date'")
    #
    #
    # expected_headers = {
    #     "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
    #     "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
    #     "access-control-allow-origin": "*",
    #     "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
    #     "allow": 'GET, HEAD, OPTIONS',
    #     "content-type": "application/json",
    #     "referrer-policy": "same-origin",
    #     "server": "nginx",
    #     "vary": "Accept",
    #     "x-content-type-options": "nosniff",
    #     "x-frame-options": "DENY"
    # }
    # for header, expected_value in expected_headers.items():
    #     assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
    #     assert  response.headers[header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
    # print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")

# def test_auth_payments():
#     url = f'{BASE_URL}api/v1/auth/payments'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     print("Response body:", response.text)
#
#     def handle_404(response):
#         print("Test successful : API = 404")
#         data = response.json()
#         assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#         assert data["details"] == "Не найден контрагент", "Ответ не содержит информации 'Не найден контрагент'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#
#     def handle_403(response):
#         print("Test successful : API = 403")
#         data = response.json()
#         assert "status" in data, "Ответ не содержит ключ 'status'"
#         assert "details" in data, "Ответ не содержит ключ 'details'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#
#     def handle_200(response):
#         print("Test successful : API = 200")
#         data = response.json()
#         assert "id" in data, "Ответ не содержит ключ 'id'"
#         assert "sum" in data, "Ответ не содержит ключ 'sum'"
#         assert "type" in data, "Ответ не содержит ключ 'type'"
#         assert "user" in data, "Ответ не содержит ключ 'user'"
#         assert "partner" in data, "Ответ не содержит ключ 'partner'"
#         assert "comment" in data, "Ответ не содержит ключ 'comment'"
#         assert "date" in data, "Ответ не содержит ключ 'date'"
#         print("Тест пройден: ответ содержит корректные поля 'id', 'sum', 'type', 'user', 'partner', 'comment' и 'date'")
#
#     handler_dict = {
#         404: handle_404,
#         403: handle_403,
#         200: handle_200
#     }
#
#     handler_dict.get(response.status_code,
#                      lambda response: (False, print(f"Непредвиденный код ответа: {response.status_code}")))(response)
#
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'GET, HEAD, OPTIONS',
#         "content-type": "application/json",
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

""" Как получить 200?"""
# def test_auth_profile_read():
#     url = f'{BASE_URL}api/v1/auth/profile'
#     headers = {
#         "accept": "application/json",
#
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     assert  response.status_code == 404
#     print("Test successful : API = 404")
#     data = response.json()
#     assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#     assert data["details"] == "Не найден контрагент", "Ответ не содержит информации 'Не найден контрагент'"
#     print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
    # assert response.status_code == 401
    # print("Test successful : API = 401")
    # data = response.json()
    # assert "status" in data, "Ответ не содержит ключ 'status'"
    # assert "details" in data, "Ответ не содержит ключ 'details'"
    # print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
        # elif response.status_code == 200:
        #     print("Test successful : API = 200")
        #     data = response.json()
        #     assert "id" in data, "Ответ не содержит ключ 'id'"
        #     assert "sum" in data, "Ответ не содержит ключ 'sum'"
        #     assert "type" in data, "Ответ не содержит ключ 'type'"
        #     assert "user" in data, "Ответ не содержит ключ 'user'"
        #     assert "partner" in data, "Ответ не содержит ключ 'partner'"
        #     assert "comment" in data, "Ответ не содержит ключ 'comment'"
        #     assert "date" in data, "Ответ не содержит ключ 'date'"
        #     print("Тест пройден: ответ содержит корректные поля 'id', 'sum', 'type', 'user', 'partner', 'comment' и 'date'")
        #


""" Как получить 200?"""
# def test_auth_profile_update():
#     url = f'{BASE_URL}api/v1/auth/profile'
#     headers = {
#         "accept": "application/json",
#         "Content-Type": "application/json",
#         "X-CSRFToken": token
#     }
#     data = {
#         "username": "string",
#         "password": "string"
#     }
#     response = requests.post(url, headers=headers, json=data)
#     if response.status_code == 404:
#         print("Test successful : API = 404")
#         data = response.json()
#         assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#         assert data["details"] == "Не найден контрагент", "Ответ не содержит информации 'Не найден контрагент'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#     elif response.status_code == 403:
#         print("Test successful : API = 403")
#         data = response.json()
#         assert "status" in data, "Ответ не содержит ключ 'status'"
#         assert "details" in data, "Ответ не содержит ключ 'details'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#     elif response.status_code == 401:
#         print("Test successful : API = 403")
#         data = response.json()
#         assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#         assert data["details"] == "Unauthorized", "Ответ не содержит информации 'Unauthorized'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#         data = {
#             "username": username,
#             "password": password
#         }
#         response = requests.post(url, headers=headers, json=data)
#     elif response.status_code == 200:
#         print("Test successful : API = 200")
#         data = response.json()
#         assert "id" in data, "Ответ не содержит ключ 'id'"
#         assert "is_active" in data, "Ответ не содержит ключ 'is_active'"
#         assert "name" in data, "Ответ не содержит ключ 'name'"
#         assert "phone" in data, "Ответ не содержит ключ 'phone'"
#         assert "email" in data, "Ответ не содержит ключ 'email'"
#         print("Тест пройден: ответ содержит корректные поля ")
#
#     else:
#         assert False, f"Непредвиденный код ответа: {response.status_code}"
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'GET, POST, HEAD, OPTIONS',
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert  response.headers[header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")




# def test_auth_register()
""" СКАЗАНО РЕГЕСТРАЦИЮ НЕ ДЕЛАТЬ"""



"""Код 500 Как получить 201?"""
# def test_auth_restore():
#     url = f'{BASE_URL}api/v1/auth/restore'
#     headers = {
#         "accept": "application/json",
#         "Content-Type": "application/json",
#         "X-CSRFToken": token
#     }
#
#     data = {
#         "username": username,
#         "password": password
#     }
#     response = requests.post(url, headers=headers, json=data)
#     print("Response body:", response.text)
#     if response.status_code == 500:
#         print("Test successful : API = 500")
#         assert "Server Error (500)" in response.text, "Ответ не содержит 'Server Error (500)'"
#         print("Тест пройден: ответ содержит 'Server Error (500)'")
#
#     elif response.status_code == 201:
#         print("Test successful : API = 201")
#         assert data["username"] == "string", "Fail"
#         assert data["password"] == "string", "Fail"
#         print("Тест пройден: ответ содержит корректные поля  для кода 201")
#     else:
#         assert False, f"Непредвиденный код ответа: {response.status_code}"
#
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "content-type": "text/html",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert  response.headers[header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")

"""Как получить 200"""
# def test__auth_restore_restore_confirm():
#      url = f'{BASE_URL}api/v1/auth/restore/confirm/{token}'
#      headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#      }
#
#      response = requests.get(url, headers=headers)
#
#
#      if response.status_code == 404:
#         print("Test successful : API = 404")
#         assert "Не удалось восстановить пароль, обратитесь к вашему менеджеру" in response.text, "Не удалось восстановить пароль, обратитесь к вашему менеджеру"
#         print("Test successful : API = 404")
#      elif response.status_code == 200:
#          data = response.json()
#          print("Test successful : API = 200")
#          assert data["username"] == "string", "Fail"
#          assert data["password"] == "string", "Fail"
#          print("Тест пройден: ответ содержит корректные поля  для кода 200")
#      else:
#          assert False, f"Непредвиденный код ответа: {response.status_code}"
#      expected_headers = {
#          "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#          "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#          "access-control-allow-origin": "*",
#          "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#          "allow": 'GET, HEAD, OPTIONS',
#          "content-type": "text/html; charset=utf-8",
#          "referrer-policy": "same-origin",
#          "server": "nginx",
#          "vary": "Accept",
#          "x-content-type-options": "nosniff",
#          "x-frame-options": "DENY"
#      }
#      for header, expected_value in expected_headers.items():
#          assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#          assert response.headers[
#                     header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#      print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")



""" Как получить 200"""

#
# def test_cancels_list():
#     url = f'{BASE_URL}api/v1/cancels'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     if response.status_code == 404:
#         print("Test successful : API = 404")
#         assert response.status_code == 404, f"Ожидается код 404, получен {response.status_code}"
#         print("Test successful : API = 404")
#         data = response.json()
#         assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#         assert data["details"] == "Неверный контрагент", "Ответ не содержит информации 'Неверный контрагент'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#     elif response.status_code == 200:
#         print("Test successful : API = 200")
#         data = response.json()
#         assert data["id"] == "integer", "Ответ не содержит статуса 'integer"
#         assert data["product_id"] == "string", "Ответ не содержит статуса 'string"
#         assert data["sku"] == "string", "Ответ не содержит статуса 'string"
#         assert data["ext_sku"] == "string", "Ответ не содержит статуса 'string"
#         assert data["name"] == "string", "Ответ не содержит статуса 'string"
#         assert data["image"] == "string", "Ответ не содержит статуса 'string"
#         assert data["cost"] == "string", "Ответ не содержит статуса 'string"
#         assert data["user"] == "string", "Ответ не содержит статуса 'string"
#         assert data["date"] == "string", "Ответ не содержит статуса 'string"
#     elif response.status_code == 403:
#         print("Test successful : API = 403")
#         data = response.json()
#         assert data["status"] == "string", "Ответ не содержит статуса 'string"
#         assert data["details"] == "string", "Ответ не содержит статуса 'string"
#     else:
#         assert False, f"Непредвиденный код ответа: {response.status_code}"

#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'GET, HEAD, OPTIONS',
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert  response.headers[header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")
#
# # #




""" Как получить 200?"""
# def test_cart_list():
#     url = f'{BASE_URL}api/v1/cart'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     if response.status_code == 404:
#         print("Test successful : API = 404")
#         data = response.json()
#         assert response.status_code == 404 , f"Ожидается код 404, получен {response.status_code}"
#         assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#         assert data["details"] == "Неверный контрагент", "Ответ не содержит информации 'Неверный контрагент'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#     elif response.status_code == 403:
#         print("Test successful : API = 403")
#         data = response.json()
#         assert response.status_code == 403 , f"Ожидается код 403, получен {response.status_code}"
#         assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#         assert data["details"] == "Cart error", "Ответ не содержит информации 'Cart error'"
#         print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#     elif response.status_code == 200:
#         print("Test successful : API = 200")
#         data = response.json()
#         assert data["products"] == "string", "Ответ не содержит статуса 'string"
#         assert data["total"] == "string", "Ответ не содержит статуса 'string"
#         assert data["currency"] == "string", "Ответ не содержит статуса 'string"
#     else:
#         assert False, f"Непредвиденный код ответа: {response.status_code}"

    # expected_headers = {
    #     "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
    #     "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
    #     "access-control-allow-origin": "*",
    #     "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
    #     "allow": 'GET, HEAD, OPTIONS',
    #     "content-type": "application/json",
    #     "referrer-policy": "same-origin",
    #     "server": "nginx",
    #     "vary": "Accept",
    #     "x-content-type-options": "nosniff",
    #     "x-frame-options": "DENY"
    # }
    # for header, expected_value in expected_headers.items():
    #     assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
    #     assert response.headers[
    #                header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
    # print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")





#____________________________________________________________

""" Как получить 200"""

#
# def test_cart_add():
#     url = f'{BASE_URL}api/v1/cart/add'
#     headers = {
#         "accept": 'application/json',
#         "Content-Type": "application/json",
#         "X-CSRFToken": token
#     }
#
#     data = [
#         {"contract": 150, "sku": "00001234", "quantity": 3},
#         {"contract": 151, "sku": "00005678", "quantity": 5}
#     ]
#     response = requests.post(url, headers=headers, json=data)
#
#     if response.status_code == 404:
#         response_data = response.json()
#         assert response_data['status'] == 'Fail'
#         assert response_data['details'] == 'Неверный контрагент'
#         print("Тест пройден: ответ содержит корректный код 404 и корректное содержание")
#     else:
#         assert False, f"Непредвиденный код ответа: {response.status_code}"
#
    # data ={
    #     "contract": 150,
    #     "sku": "00001234",
    #     "quantity": 3
    # }
#     response = requests.post(url, headers=headers, json=data)
#
#     if response.status_code == 404:
#         response_data = response.json()
#         assert response_data['status'] == 'Fail'
#         assert response_data['details'] == 'Неверный контрагент'
#         print("Тест пройден: ответ содержит корректный код 404 и корректное содержание")
#     elif response.status_code == 200:
#         print("Test successful : API = 200")
#         data = response.json()
#         assert data["status"] == "string", "Ответ не содержит статуса 'string"
#         assert data["details"] == "string", "Ответ не содержит статуса 'string"
#     else:
#         assert False, f"Непредвиденный код ответа: {response.status_code}"
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'POST, OPTIONS',
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert response.headers[
#                    header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")

#







""" Как полуить 200"""
#
# def test_categories_list():
#     url = f'{BASE_URL}api/v1/categories'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": "barwWL1IsupMdLXYtT8SxFQNzoprMji9UsLPrP555VANm8dMEiy6iBRML5kZJBCs"
#     }
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 404, f"Ожидается код 404, получен {response.status_code}"
#     print("Test successful : API = 404")
#     data = json.loads(response.text)
#     assert data["status"] == "Fail", "Ответ не содержит статуса 'Fail"
#     assert data["details"] == "Неверный контрагент", "Ответ не содержит информации 'Неверный контрагент'"
#     print("Тест пройден: ответ содержит корректные поля 'status' и 'details'")
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'GET, HEAD, OPTIONS',
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert response.headers[
#                    header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")
#

""" В этом тесте приходит 200, но
ключи должны быть строкой, и приходит строка,
а получаем ошибку, что должна быть int
 TypeError: string indices must be integers, not 'str
  и опять тест может приходить 200 с кривым токином'
"""

# def test_cities_list():
#     url = f'{BASE_URL}api/v1/cities'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"
#
#     print("Test successful : API = 200")
#     data = response.json()
#
#
#     assert len(data) > 0, f" Не верно, пришла {data}"
#
#     for item in data:
#
#         assert item["status"] == "string", f" Не верно, пришла {data}"
#         assert item["details"] == "string", f" Не верно, пришла {data}"
#
#
#
#     expected_headers = {
#         "access-control-allow-headers": "*, DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
#         "access-control-allow-methods": "GET, POST, OPTIONS, DELETE, HEAD",
#         "access-control-allow-origin": "*",
#         "access-control-expose-headers": 'Content-Disposition, Content-Length,Content-Range',
#         "allow": 'GET, HEAD, OPTIONS',
#         "content-type": "application/json",
#         "referrer-policy": "same-origin",
#         "server": "nginx",
#         "vary": "Accept",
#         "x-content-type-options": "nosniff",
#         "x-frame-options": "DENY"
#     }
#     for header, expected_value in expected_headers.items():
#         assert header in response.headers, f"Ответ не содержит заголовок '{header}'"
#         assert response.headers[
#                    header] == expected_value, f"Ожидалось значение '{expected_value}', получено '{response.headers[header]}'"
#     print("Тест пройден: все ожидаемые заголовки присутствуют и имеют корректные значения")

"""api_v1_compare Нужно ids """



"""с кривым токеном тоже приходит 200"""
# def test_currencies_list():
#     url = f'{BASE_URL}api/v1/currencies'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#
#     data = response.json()
#
#     assert isinstance(data, list), "Ответ должен быть списком"
#
#
#     for item in data:
#         assert isinstance(item, dict), "Каждый элемент списка должен быть словарем"
#         assert "id" in item, "Каждый элемент должен содержать ключ 'id'"
#         assert "value" in item, "Каждый элемент должен содержать ключ 'value'"
#         assert "code" in item, "Каждый элемент должен содержать ключ 'code'"
#         assert "name" in item, "Каждый элемент должен содержать ключ 'name'"
#
#         assert isinstance(item["id"], int), "Поле 'id' должно быть целым числом"
#         assert isinstance(item["value"], int), "Поле 'value' должно быть целым числом"
#         assert isinstance(item["code"], str), "Поле 'code' должно быть строкой"
#         assert isinstance(item["name"], str), "Поле 'name' должно быть строкой"
#
#         assert item["id"] > 0, "Поле 'id' должно быть положительным числом"
#         assert item["value"] > 0, "Поле 'value' должно быть положительным числом"
#     print("Тест пройден")



# def test_cities_list_404():
#     url = f'{BASE_URL}api/v1/cities'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token_bad
#     }
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"
#

# def  test_faq_list_404():
#     url = f'{BASE_URL}api/v1/faq_bad_404'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 404, f"Ожидаемый код состояния 404, получен {response.status_code}"
#
#     try:
#         data = response.json()
#     except Exception as e:
#         print(f"Ошибка при преобразовании ответа в JSON: {e}")
#         return
#     assert "status" in data, f"Не найден ключ 'status' в ответе: {data}"
#     assert "details" in data, f"Не найден ключ 'details' в ответе: {data}"
#     assert data["status"] == "Fail", f"Ожидаемое значение 'Fail', получено {data['status']}"
#     assert data["details"] == "Not found", f"Ожидаемое значение 'Not found', получено {data['details']}"
#
#     print("Тест пройден")
#


# def get_first_faq_id():
#     url = f'{BASE_URL}api/v1/faq'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#
#     data = response.json()
#
#     first_faq = data[0]
#
#     return first_faq["id"]

#
#
# from datetime import datetime
# def test_faq_list():
#
#     url = f'{BASE_URL}api/v1/faq'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#
#     data = response.json()
#     assert len(data) > 0, f" Не верно, пришла {data}"
#     prev_date = None
#     for item in data:
#         assert isinstance(item, dict), f" Не верно, пришла {data}"
#         assert "id" in item, f" Не верно, пришла {data}"
#         assert "question" in item and isinstance(item["question"],
#                                                str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#         assert "date" in item and isinstance(item["date"],
#                                              str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#
#         # Проверка сортировки по убыванию даты
#
#         date = datetime.strptime(item["date"], "%d.%m.%y")
#         if prev_date is not None:
#             assert date <= prev_date, f" Не верно, список не отсортирован по убыванию даты: {data}"
#         prev_date = date
#
#
#
# print("Тест пройден")
#
#
# def str_to_datetime_FAQ(date_str):
#     return datetime.strptime(date_str, "%d.%m.%y")
#
#
# def test_faq_read():
#     faq_id = get_first_faq_id()
#     url = f'{BASE_URL}api/v1/faq/{faq_id}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#
#     data = response.json()
#
#     assert isinstance(data["id"], int), f"Ожидаемый тип данных для 'id' - int, получен {type(data['id'])}"
#     assert "question" in data and isinstance(data["question"],
#                                              str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#     assert "answer" in data and isinstance(data["question"],
#                                              str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#     assert "date" in data and isinstance(data["date"],
#                                              str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#     assert "next" in data and (data["next"] is None or isinstance(data["next"],
#                                                                   int)), f"Не найден ключ 'next' или его значение имеет тип {type(data['next'])}: {data}"
#     assert "prev" in data and (data["prev"] is None or isinstance(data["prev"],
#                                                                   int)), f"Не найден ключ 'prev' или его значение имеет тип {type(data['prev'])}: {data}"

#     next_url = f'{BASE_URL}api/v1/faq/{data["next"]}'
#     prev_url = f'{BASE_URL}api/v1/faq/{data["prev"]}'
#
#     next_response = requests.get(next_url, headers=headers)
#     prev_response = requests.get(prev_url, headers=headers)
#
#     assert next_response.status_code in (
#     200, 404), f"Ожидаемый код состояния 200 или 404, получен {next_response.status_code}"
#     assert prev_response.status_code in (
#     200, 404), f"Ожидаемый код состояния 200 или 404, получен {prev_response.status_code}"
#     current_date = str_to_datetime_FAQ(data["date"])
#
#     if next_response.status_code == 200:
#         next_data = next_response.json()
#         next_date = str_to_datetime_FAQ(next_data["date"])
#         assert current_date >= next_date, f"Текущая дата меньше следующей: {data}"
#
#     if prev_response.status_code == 200:
#         prev_data = prev_response.json()
#         prev_date = str_to_datetime_FAQ(prev_data["date"])
#         assert current_date <= prev_date, f"Текущая дата больше предыдущей: {data}"
#



""" Я считаю это баг. В первом тесте соблюдается
 последовательность по убыванию дат , а в следующем тесте нет """

# def test_news_list_id():
#     url = f'{BASE_URL}api/v1/news'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#
#     data = response.json()
#
#     midle_news_ID = data[1]
#
#     return midle_news_ID["id"]
#
# def test_news_list():
#     url = f'{BASE_URL}api/v1/news'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#
#     data = response.json()
#     assert len(data) > 0, f" Не верно, пришла {data}"
#     prev_date = None
#     for item in data:
#         assert isinstance(item, dict), f" Не верно, пришла {data}"
#         assert "id" in item, f" Не верно, пришла {data}"
#
#         assert "title" in item and isinstance(item["title"],
#                                               str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#         assert "short" in item and isinstance(item["short"],
#                                               str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#         assert "text" in item and isinstance(item["text"],
#                                               str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#         assert "image" in item and isinstance(item["image"],
#                                              str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#         assert "date" in item and isinstance(item["date"],
#                                              str), f"Не найден ключ 'question' или его значение не является строкой: {data}"
#
#         # Проверка сортировки по убыванию даты
#
#         date = datetime.strptime(item["date"], "%d.%m.%y")
#         if prev_date is not None:
#             assert date <= prev_date, f" Не верно, список не отсортирован по убыванию даты: {data}"
#         prev_date = date
#
#
# def str_to_datetime(date_str):
#     return datetime.strptime(date_str, "%d.%m.%y")
#
# def test_news_list_read():
#     midle_id = test_news_list_id()
#     url = f'{BASE_URL}api/v1/news/{midle_id}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#
#     data = response.json()
#     assert len(data) > 0, f" Не верно, пришла {data}"
#
#     assert "id" in data, f" Не верно, пришла {data}"
#
#     assert "title" in data and isinstance(data["title"],
#                                           str), f"Не найден ключ 'title' или его значение не является строкой: {data}"
#     assert "short" in data and isinstance(data["short"],
#                                           str), f"Не найден ключ 'short' или его значение не является строкой: {data}"
#
#     assert "text" in data and isinstance(data["text"],
#                                           str), f"Не найден ключ 'text' или его значение не является строкой: {data}"
#     assert "image" in data and isinstance(data["image"],
#                                          str), f"Не найден ключ 'image' или его значение не является строкой: {data}"
#     assert "date" in data and isinstance(data["date"],
#                                          str), f"Не найден ключ 'date' или его значение не является строкой: {data}"
#     assert "next" in data and (data["next"] is None or isinstance(data["next"],
#                                                                   int)), f"Не найден ключ 'next' или его значение имеет тип {type(data['next'])}: {data}"
#     assert "prev" in data and (data["prev"] is None or isinstance(data["prev"],
#                                                                   int)), f"Не найден ключ 'prev' или его значение имеет тип {type(data['prev'])}: {data}"

#
#     next_url = f'{BASE_URL}api/v1/news/{data["next"]}'
#     prev_url = f'{BASE_URL}api/v1/news/{data["prev"]}'
#
#     next_response = requests.get(next_url, headers=headers)
#     prev_response = requests.get(prev_url, headers=headers)
#
#     assert next_response.status_code == 200, f"Ожидаемый код состояния 200, получен {next_response.status_code}"
#     assert prev_response.status_code == 200, f"Ожидаемый код состояния 200, получен {prev_response.status_code}"
#
#     next_data = next_response.json()
#     prev_data = prev_response.json()
#
#     current_date = str_to_datetime(data["date"])
#     next_date = str_to_datetime(next_data["date"])
#     prev_date = str_to_datetime(prev_data["date"])
#
#     assert current_date <= prev_date, f"Текущая дата больше предыдущей: {data}"
#     assert current_date >= next_date, f"Текущая дата меньше следующей: {data}"
#
""" Необходима для корректировки проверить
 в каком виде должны быть значение ключей, 
 потому что часто встречаются в Свагере ошибки """

# def test_order_filters():
#
#     url = f'{BASE_URL}api/v1/order/filters'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#     data = response.json()
#     assert isinstance(data, list), f"Ожидается список, получено {type(data)}"
#     assert len(data) > 0, "Список пуст"
#
#     for item in data:
#         assert "id" in item and isinstance(item["id"],
#                                            str), f"Не найден ключ 'id' или его значение имеет тип {type(item['id'])}: {item}"
#         assert "name" in item and isinstance(item["name"],
#                                              str), f"Не найден ключ 'name' или его значение имеет тип {type(item['name'])}: {item}"
#         assert "type" in item and isinstance(item["type"],
#                                              str), f"Не найден ключ 'type' или его значение имеет тип {type(item['type'])}: {item}"
#         assert "data" in item and isinstance(item["data"],
#                                              dict), f"Не найден ключ 'data' или его значение имеет тип {type(item['data'])}: {item}"
#
#         if "order_id" in item:
#             assert isinstance(item["order_id"],
#                               str), f"Ожидаемый тип данных для 'order_id' - str, получен {type(item['order_id'])}: {item}"
#         if "contract" in item:
#             assert isinstance(item["contract"],
#                               str), f"Ожидаемый тип данных для 'contract' - str, получен {type(item['contract'])}: {item}"
#         if "company" in item:
#             assert isinstance(item["company"],
#                               str), f"Ожидаемый тип данных для 'company' - str, получен {type(item['company'])}: {item}"
#         if "status" in item:
#             assert isinstance(item["status"],
#                               str), f"Ожидаемый тип данных для 'status' - str, получен {type(item['status'])}: {item}"
#         if "total" in item:
#             assert isinstance(item["total"],
#                               str), f"Ожидаемый тип данных для 'total' - str, получен {type(item['total'])}: {item}"
#         if "currency" in item:
#             assert isinstance(item["currency"],
#                               str), f"Ожидаемый тип данных для 'currency' - str, получен {type(item['currency'])}: {item}"
#         if "weight" in item:
#             assert isinstance(item["weight"],
#                               str), f"Ожидаемый тип данных для 'weight' - str, получен {type(item['weight'])}: {item}"
#         if "volume" in item:
#             assert isinstance(item["volume"],
#                               str), f"Ожидаемый тип данных для 'volume' - str, получен {type(item['volume'])}: {item}"
#         if "partner" in item:
#             assert isinstance(item["partner"],
#                               str), f"Ожидаемый тип данных для 'partner' - str, получен {type(item['partner'])}: {item}"
#         if "user" in item:
#             assert isinstance(item["user"],
#                               str), f"Ожидаемый тип данных для 'user' - str, получен {type(item['user'])}: {item}"
#         if "comment" in item:
#             assert isinstance(item["comment"],
#                               str), f"Ожидаемый тип данных для 'comment' - str, получен {type(item['comment'])}: {item}"
#         if "delivery" in item:
#             assert isinstance(item["delivery"],
#                               str), f"Ожидаемый тип данных для 'delivery' - str, получен {type(item['delivery'])}: {item}"
#         if "error" in item:
#             assert isinstance(item["error"],
#                               str), f"Ожидаемый тип данных для 'error' - str, получен {type(item['error'])}: {item}"
#         if "updated" in item:
#             assert isinstance(item["updated"],
#                               str), f"Ожидаемый тип данных для 'updated' - str, получен {type(item['updated'])}: {item}"
#         if "created" in item:
#             assert isinstance(item["created"],
#                               str), f"Ожидаемый тип данных для 'created' - str, получен {type(item['created'])}: {item}"
#
#         data_dict = item["data"]
#         assert "popular_dictionary_values" in data_dict and isinstance(data_dict["popular_dictionary_values"],
#                                                                        list), f"Не найден ключ 'popular_dictionary_values' или его значение имеет тип {type(data_dict['popular_dictionary_values'])}: {data_dict}"
#         assert "options" in data_dict and isinstance(data_dict["options"],
#                                                      list), f"Не найден ключ 'options' или его значение имеет тип {type(data_dict['options'])}: {data_dict}"
#
#         for option in data_dict["options"]:
#             assert "id" in option and isinstance(option["id"],
#                                                  int), f"Не найден ключ 'id' или его значение имеет тип {type(option['id'])}: {option}"
#             assert "name" in option and isinstance(option["name"],
#                                                    str), f"Не найден ключ 'name' или его значение имеет тип {type(option['name'])}: {option}"
#
#






""" Непонятно как отправлять POST JSON [1, 2, 3, 4, 5]"""
# def test_order_merge():
#     url = f'{BASE_URL}api/v1/order/merge'
#     headers = {
#         "accept": "application/json",
#         "Content-Type": "application/json",
#         "X-CSRFToken": token
#     }
#     data = [1, 2, 3, 4, 5]
#
#     response = requests.post(url, json=data, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"


# def test_order_types():
#
    # url = f'{BASE_URL}api/v1/order/types'
    # headers = {
    #     "accept": "application/json",
    #     "X-CSRFToken": token
    # }

#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"
#     data = response.json()
#     assert isinstance(data, list), f"Ожидается список, получено {type(data)}"
#     assert len(data) > 0, "Список пуст"
#
#     for item in data:
#         assert "id" in item, f"Не найден ключ 'id': {item}"
#         assert isinstance(item["id"], int), f"Ожидаемый тип данных для 'id' - int, получен {type(item['id'])}: {item}"
#
#         assert "value" in item, f"Не найден ключ 'value': {item}"
#         assert isinstance(item["value"],
#                           int), f"Ожидаемый тип данных для 'value' - int, получен {type(item['value'])}: {item}"
#
#         assert "name" in item, f"Не найден ключ 'name': {item}"
#         assert isinstance(item["name"],
#                           str), f"Ожидаемый тип данных для 'name' - str, получен {type(item['name'])}: {item}"
#
#         if "order_id" in item:
#             assert isinstance(item["order_id"],
#                               str), f"Ожидаемый тип данных для 'order_id' - str, получен {type(item['order_id'])}: {item}"
#
#         if "contract" in item:
#             assert isinstance(item["contract"],
#                               str), f"Ожидаемый тип данных для 'contract' - str, получен {type(item['contract'])}: {item}"
#
#         if "company" in item:
#             assert isinstance(item["company"],
#                               str), f"Ожидаемый тип данных для 'company' - str, получен {type(item['company'])}: {item}"
#
#         if "status" in item:
#             assert isinstance(item["status"],
#                               str), f"Ожидаемый тип данных для 'status' - str, получен {type(item['status'])}: {item}"
#
#         if "total" in item:
#             assert isinstance(item["total"],
#                               str), f"Ожидаемый тип данных для 'total' - str, получен {type(item['total'])}: {item}"
#
#         if "currency" in item:
#             assert isinstance(item["currency"],
#                               str), f"Ожидаемый тип данных для 'currency' - str, получен {type(item['currency'])}: {item}"
#
#         if "weight" in item:
#             assert isinstance(item["weight"],
#                               str), f"Ожидаемый тип данных для 'weight' - str, получен {type(item['weight'])}: {item}"
#
#         if "volume" in item:
#             assert isinstance(item["volume"],
#                               str), f"Ожидаемый тип данных для 'volume' - str, получен {type(item['volume'])}: {item}"
#
#         if "partner" in item:
#             assert isinstance(item["partner"],
#                               str), f"Ожидаемый тип данных для 'partner' - str, получен {type(item['partner'])}: {item}"
#
#         if "user" in item:
#             assert isinstance(item["user"],
#                               str), f"Ожидаемый тип данных для 'user' - str, получен {type(item['user'])}: {item}"
#
#         if "comment" in item:
#             assert isinstance(item["comment"],
#                               str), f"Ожидаемый тип данных для 'comment' - str, получен {type(item['comment'])}: {item}"
#
#         if "delivery" in item:
#             assert isinstance(item["delivery"],
#                               str), f"Ожидаемый тип данных для 'delivery' - str, получен {type(item['delivery'])}: {item}"
#
#         if "error" in item:
#             assert isinstance(item["error"], (
#             str, type(None))), f"Ожидаемый тип данных для 'error' - str или None, получен {type(item['error'])}: {item}"
#
#         if "updated" in item:
#             assert isinstance(item["updated"],
#                               str), f"Ожидаемый тип данных для 'updated' - str, получен {type(item['updated'])}: {item}"
#
#         if "created" in item:
#             assert isinstance(item["created"],
#                               str), f"Ожидаемый тип данных для 'created' - str, получен {type(item['created'])}: {item}"



"""Где брать id, с предыдущего кода не подходят"""


# def test_order_read():
#     url = f'{BASE_URL}api/v1/order/{id}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }


"""Где брать id, """

# def test_order_delivery():
#     url = f'{BASE_URL}api/v1/order/{id}/delivery'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }


"""Где брать id, """

# def test_order_delivery_delivery_dates():
#     url = f'{BASE_URL}api/v1/order/{id}/delivery/dates'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }



"""Где брать id, """

# def test_order_delivery_dereserve_read():
#     url = f'{BASE_URL}api/v1/order/{id}/dereserve'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }

"""Где брать id, """

# def test_order_delivery_dereserve_create():
#     url = f'{BASE_URL}api/v1/order/{id}/dereserve'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }

"""Где брать id, """

# def test_order_invoice():
#     url = f'{BASE_URL}api/v1/order/{id}/invoice'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }


"""Где брать id, """

# def test_order_reserve_read():
#     url = f'{BASE_URL}api/v1/order/{id}/reserve'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }



"""Где брать id, """

# def test_order_reserve_create():
#     url = f'{BASE_URL}api/v1/order/{id}/reserve'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }


"""Где брать id, """

# def test_order_undelivery():
#     url = f'{BASE_URL}api/v1/order/{id}/undelivery'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }


"""где брать {user_id}{slug_link}"""

"""api_v1_promotion_list там в респонс бади просто [] и 
больше ни чего"""


# def test_quick():
#     url = f'{BASE_URL}api/v1/qsearch/'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код ответа: 200, получен: {response.status_code}"
#
#     data = response.json()
#     assert "count" in data, "Отсутствует ключ 'count' в ответе"
#     assert "categories" in data, "Отсутствует ключ 'categories' в ответе"
#     assert "products" in data, "Отсутствует ключ 'products' в ответе"
#
#
#     assert isinstance(data["count"],
#                       int), f"Ожидаемый тип данных для 'count' - int, получен {type(data['count'])}: {data}"
#     assert data["categories"] is None or isinstance(data["categories"],
#                                                     list), f"Ожидаемый тип данных для 'categories' - None или list, получен {type(data['categories'])}: {data}"
#     assert data["products"] is None or isinstance(data["products"],
#                                                   list), f"Ожидаемый тип данных для 'products' - None или list, получен {type(data['products'])}: {data}"


""" Гле брать keyword"""

# keyword = 1
# def test_quick():
#     url = f'{BASE_URL}api/v1/qsearch/{keyword}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код ответа: 200, получен: {response.status_code}"
#
#     data = response.json()
#     assert "count" in data, "Отсутствует ключ 'count' в ответе"
#     assert "categories" in data, "Отсутствует ключ 'categories' в ответе"
#     assert "products" in data, "Отсутствует ключ 'products' в ответе"
#
#     assert isinstance(data["count"],
#                       int), f"Ожидаемый тип данных для 'count' - int, получен {type(data['count'])}: {data}"
#     assert data["categories"] is None or isinstance(data["categories"],
#                                                     list), f"Ожидаемый тип данных для 'categories' - None или list, получен {type(data['categories'])}: {data}"
#     assert data["products"] is None or isinstance(data["products"],
#                                                   list), f"Ожидаемый тип данных для 'products' - None или list, получен {type(data['products'])}: {data}"


"""Что проверять при ошибке 500"""
# def test_search():
#     url = f'{BASE_URL}api/v1/search'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }


"""Что проверять при ошибке и где брать Id  500"""
# api_v1_suppliers_list


"""Ответ приходит обычным текстом. Не json. Это нормально или баг?"""
#
# def test_synonims_list():
#     url = f'{BASE_URL}api/v1/synonims'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200
#
#     try:
#         synonims = response.json()
#     except json.JSONDecodeError:
#         print("Response is not a valid JSON string. Handling as plain text.")
#         synonims = response.text
#
#     if isinstance(synonims, str):
#         print("Ошибка: ожидался JSON, но получена текстовая строка")
#         return  # Завершаем выполнение теста
#
#     for synonim in synonims:
#         assert 'id' in synonim
#         assert isinstance(synonim['id'], int)
#
#         assert 'name' in synonim
#         assert isinstance(synonim['name'], str)
#
#         assert 'sku' in synonim
#         assert isinstance(synonim['sku'], str)
#
#         assert 'image' in synonim
#         assert isinstance(synonim['image'], str)
#
#         assert 'stock' in synonim
#         assert isinstance(synonim['stock'], str)
#
#         assert 'available' in synonim
#         assert isinstance(synonim['available'], str)
#
#         assert 'date' in synonim
#         assert isinstance(synonim['date'], str)

#
# def get_vendor_list_id():
#     url = f'{BASE_URL}api/v1/vendor/'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#
#     data = response.json()
#
#     vendor_id = data[0]
#
#     return vendor_id["id"]
#
# """ этот тест почему то проходит и с кривым токином"""
#
# def test_vendor_list():
#     url = f'{BASE_URL}api/v1/vendor'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200
#
#     vendors = response.json()
#
#     for vendor in vendors:
#         assert 'id' in vendor
#         assert isinstance(vendor['id'], int)
#
#         assert 'name' in vendor
#         assert isinstance(vendor['name'], str)
#         assert 1 <= len(vendor['name']) <= 256
#
#         if vendor['image'] is not None:
#             assert isinstance(vendor['image'], str)
#
# def test_vendor_read():
#     first_id = get_vendor_list_id()
#     url = f'{BASE_URL}api/v1/vendor/{first_id}'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200
#
#     vendor = response.json()
#
#
#     assert 'id' in vendor
#     assert isinstance(vendor['id'], int)
#
#     assert 'name' in vendor
#     assert isinstance(vendor['name'], str)
#     assert 1 <= len(vendor['name']) <= 256
#     if vendor['image'] is not None:
#         assert isinstance(vendor['image'], str)
#
#     incorrect_url = f'{BASE_URL}api/v1/vendor/incorrect/'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token_bad
#     }
#     response = requests.get(incorrect_url, headers=headers)
#     # Проверяем, что код состояния не равен 200, если используются неправильный токен и URL
#     assert response.status_code != 200






