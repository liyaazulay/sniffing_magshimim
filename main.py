import re

from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from scapy.sendrecv import sniff
EXIT = "0"
DNS_OP = "1"
FORE_CAST_OP = "2"
HTTP_OP = "3"
EMAIL_OP = "4"
DELETE_END = 1
IP_MSG_FORMAT = " ===> "
ERROR_MSG = "error: "
RESPONSE_TYPE = 1
DNS_AND_FORE_CAST_SNIFF_TIMES = 2
FORE_CAST_IP = "34.218.16.79"
WELCOME_MSG = "Welcome to Magshimim's Forecast Server!"
METHOD = "GET"
MENU = "Welcome to Magshishark!\nPlease select sniffing state:\n1. DNS \n2. Forecast\n3. HTTP\n4. E-mails\nOr select 0 to Exit: "
HTTP_SNIFF_TIMES = 4


def print_ip(packet):
    try:
        domain = packet[DNS].qd.qname.decode()
        domain_without_dot = domain[:-DELETE_END]
        print(domain_without_dot + IP_MSG_FORMAT + packet[DNS].an.rdata)
    except Exception as e:
        print(ERROR_MSG, e)


def is_dns_response(packet):
    return DNS in packet and packet[DNS].an is not None and packet[DNS].qr == RESPONSE_TYPE and packet[DNS].an.type == RESPONSE_TYPE


def sniff_dns():
    sniff(count=DNS_AND_FORE_CAST_SNIFF_TIMES, lfilter=is_dns_response, prn=print_ip)


def is_weather(packet):
    return TCP in packet and Raw in packet and packet[IP].src == FORE_CAST_IP and WELCOME_MSG not in packet[Raw].load.decode()


def print_weather(packet):
    print(packet[Raw].load.decode())


def sniff_fore_cast():
    sniff(count=DNS_AND_FORE_CAST_SNIFF_TIMES, lfilter=is_weather, prn=print_weather)


def is_http(packet):
    return HTTPRequest in packet and packet[HTTPRequest].Method.decode() == METHOD


def print_http(packet):
    print(packet[HTTP].Path.decode())


def sniff_http():
    sniff(count=HTTP_SNIFF_TIMES, lfilter=is_http, prn=print_http)


def is_email_shiran(packet):
    return HTTPRequest in packet and packet[HTTPRequest].Method.decode() == METHOD

def is_email(packet):
    if HTTP in packet and Raw in packet:
        load = packet[Raw].load.decode()
        if "HTTP" in load:
            # מצא את כל הכתובות האימייל בתוך התוכן של ה-HTTP באמצעות רגולריות
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', load)
            if emails:
                return True
            else:
                return False


def print_email_http(packet):
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', packet[Raw].load.decode())
    for email in emails:
        print(email)


def sniff_email():
    sniff(count=HTTP_SNIFF_TIMES, lfilter=is_email, prn=print_email_http)


def print_menu_and_get_choice():
    choice = input(MENU)
    return choice


def main():
    dict_functions = {
        DNS_OP: sniff_dns,
        FORE_CAST_OP: sniff_fore_cast,
        HTTP_OP: sniff_http,
        EMAIL_OP: sniff_email,
    }
    try:
        choice = None
        while choice != EXIT:
            choice = print_menu_and_get_choice()
            dict_functions[choice]()
    except Exception as e:
        print(ERROR_MSG, e)


if __name__ == "__main__":
    main()
