from scapy import *

# takes in http response from the server and strips it to a RAW https response to send to victim
def parse(response):
    stripped_response = "HTTP/1.1 " + str(response.status_code) + "\r\n"
    # var:response.headers is a dict; contains headers with values from https response
    for key in response.headers:
        stripped_response = stripped_response + key + ": " + response.headers.get(key) + "\r\n"

    # add html content to the http response
    stripped_response = stripped_response + "\n" + response.text + "\r\n\r\n"
    return stripped_response
