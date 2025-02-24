## Зависимости

- PostgreSQL 17
- Go 1.23.1
- ``github.com/jackc/pgx/v5`` - интеграция PostgreSQL
- ``golang.org/x/crypto`` - реализация bcrypt хеша

## Сборка
- Сборка сервера как отдельной программы: ``go build cmd/main.go``
- Сборка сервера как Docker-контейнера: ``docker build .``

## Использование
Запуск:
- ``$ server`` или
- ``$ docker run <server_container>``

Запуск с установкой переменных среды из файла:
- ``$ env $(cat config.env) server`` или
- ``$ docker run --env-file config.env <server_container>`` (см. также замечания ниже)

REST маршруты:
- ``auth`` - выдача новой пары токенов. Принимаются только ``POST`` запросы (ожидается, что ``guid`` пользователя будет передан в теле запроса в формате параметра запроса: ``guid=<GUID>``). При успешном выполнении операции возвращается JSON-объект с токенами формата ``{"access": {"token": <token>, "expires_in":<duration>}, "refresh":{"token":<token>, "expires_in":<duration>}}``. Acces-токен имеет тип JWT и сгенерирован в соответствии со [спецификацией](https://datatracker.ietf.org/doc/html/rfc7519)
- ``refresh`` - выполнение Refresh операции. Принимаются только ``POST`` запросы. Ожидается, что Access токен будет передан в заголовке ``Authorisation`` со схемой авторизации ``Bearer``, а Refresh токен - в теле запроса в формате параметра запроса: ``refresh=<token>``. При успешном выполнении операции будет возвращена новая пара токенов, в том же формате, что и для пути ``auth``

Конфигурация сервера осуществляется через переменные среды. Для успешного запуска необходимо установть переменные ``DB_URL`` (URL для подключения к БД) и ``SERVER_ADDRESS`` (TCP адрес сервера).

Список переменных:
- ``LOG_PATH`` - путь к файлу, в который будут записаны логи. По умолчанию логи пишутся в ``stderr``
- ``DB_URL`` - URL для подключения к БД
- ``ACCESS_DURATION_SEC`` - длительность валидности Access токена в секундах, по умолчанию 10 минут
- ``REFRESH_DURATION_SEC`` - длительность валидности Refresh токена в секундах, по умолчанию 10 часов
- ``EMAIL_USERNAME`` - имя пользователя для подключения к SMTP серверу
- ``EMAIL_PASSWORD`` - пароль для подключения к SMTP серверу
- ``EMAIL_AUTH_HOST`` - хост для подключения к SMTP серверу
- ``EMAIL_SERVER_ADDRESS`` - хост для отправки email предупреждений
- ``EMAIL_FROM`` - адрес почты, с которого будут отправлены предупреждения
- ``SERVER_ADDRESS`` - TCP адрес сервера

## Замечания
- Сервер предполагает, что email пользователей записан в таблице ``user_data`` с двумя столбцами: ``guid`` (GUID пользователя) ``email`` (email пользователя)
- Если отправить email предупреждение не получилось, сервер пишет в лог сообщение об ошибке, но не прерывает Refresh операцию (в описании не было четких инструкций на этот случай)
- URL БД в файле ``config.env`` предполагает, что БД и сервер расположены на одном компьютере и не будет работать при запуске Docker контейнера без параметра ``--network=host``
