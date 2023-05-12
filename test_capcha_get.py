import requests
from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest
import json
from json import JSONDecodeError
BASE_URL = 'https://api.b2b.tdx.by/'
token = "ZXKvrJZFwOeBpjEzqisc2kIWgg04l89rIf4OWN329fpCyGUnBHSqNgJVsXVCiqtK"
token_bad = "8768oyfgit76"
password = "Ms5r&jdSg"
username = "petrychcho@mediatech.dev"
email = "petrychcho@mediatech.dev"


"""api_v1_auth_captcha_read"""

# def test_auth_captcha_read_200():
#     url = f'{BASE_URL}api/v1/auth/captcha'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#     response = requests.get(url, headers=headers)
#     print("Response body:", response.text)
#
#     assert response.status_code == 200, f"Непредвиденный код ответа: {response.status_code}"
#     print("Test successful : API = 200")
#     data = json.loads(response.text)
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
#




""" Не делаю этот тест """

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
           Его не трогаем"""

# def test_auth_confirm_200():
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

# def test_cities_list_200():
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

    # assert len(data) > 0, f"Ответ должен содержать хотя бы один город, пришла {data}"
    # assert data["status"] == "string", f"Ответ должен содержать хотя бы один город, пришла {data}"
    # assert data["details"] == "string", f"Ответ должен содержать хотя бы один город, пришла {data}"
    # print("Тест пройден: ответ содержит хотя бы один город")
    # assert len(data) > 0, f" Не верно, пришла {data}"
    # assert isinstance(data, list), f" Не верно, пришла {data}"
    # assert isinstance(data[0], dict), f" Не верно, пришла {data}"
    # assert "status" in data[0], f" Не верно, пришла {data}"
    # assert "details" in data[0], f" Не верно, пришла {data}"
    # assert data[0]["status"] == "string", f" Не верно, пришла {data}"
    # assert data[0]["details"] == "string", f" Не верно, пришла {data}"
    # assert len(data) > 0, f" Не верно, пришла {data}"
    # assert isinstance(data, list), f" Не верно, пришла {data}"
    # assert isinstance(data[0], str), f" Не верно, пришла {data}"
    #
    # print("Тест пройден")
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

# def test_cities_list_404():
#     url = f'{BASE_URL}api/v1/cities'
#     headers = {
#         "accept": 'application/json',
#         "X-CSRFToken": token_bad
#     }
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидается код 200, получен {response.status_code}"

""" НЕ приходит 404, и с кривым токеном тоже приходит 200"""
# def test_currencies_list():
#     url = f'{BASE_URL}api/v1/currencies'
#     headers = {
#         "accept": "application/json",
#         "X-CSRFToken": token
#     }
#
#     response = requests.get(url, headers=headers)
#     assert response.status_code == 200, f"Ожидаемый код состояния 200, получен {response.status_code}"

#     data = response.json()
# #     assert len(data) > 0, f" Не верно, пришла {data}"
""" это более корректно . тест проходит, НО ожидания в Swagger,
 который не соответствует ответу API"""
    # for item in data:
    #     assert isinstance(item, dict), f" Не верно, пришла {data}"
    #     assert "id" in item, f" Не верно, пришла {data}"
    #     assert "value" in item, f" Не верно, пришла {data}"
    #     assert "code" in item, f" Не верно, пришла {data}"
    #     assert "name" in item, f" Не верно, пришла {data}"
    #
    # print("Тест пройден")

""" это НЕ корректно . тест НЕ проходит, НО ожидания в Swagger,
 который  соответствует ответу API"""
#     assert len(data) > 0, f" Не верно, пришла {data}"
#
#     for item in data:
#         # assert isinstance(item, dict), f" Не верно, пришла {data}"
#         # assert "status" in item, f" Не верно, пришла {data}"
#         # assert "details" in item, f" Не верно, пришла {data}"
#         assert item["status"] == "string", f" Не верно, пришла {data}"
#         assert item["details"] == "string", f" Не верно, пришла {data}"
#
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
#     url = f'{BASE_URL}api/v1/order/types'
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