from scapy import *


def parse(response):
    stripped_response = "HTTP/1.1 " + str(response.status_code) + "\r\n"
    for key in response.headers:
        stripped_response = stripped_response + key + ": " + response.headers.get(key) + "\r\n"
    stripped_response = stripped_response + "\n" + response.text + "\r\n\r\n"
    return stripped_response

#print(parse(response))