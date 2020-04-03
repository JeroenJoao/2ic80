import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import SocketServer
import sys
import base64
import ssl

key = ""

class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print "send header"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print "send header"
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global key
        ''' Present frontpage with user authentication. '''
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            pass
        elif self.headers.getheader('Authorization') == 'Basic '+key:
            SimpleHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            pass

          
def sslWrap (https_port = 8050, HandlerClass = AuthHandler, ServerClass = BaseHTTPServer.HTTPServer):

    httpd = SocketServer.TCPServer(("", https_port), HandlerClass)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile="/home/attacker/localhost.pem", server_side=True)

    sa = httpd.socket.getsockname()
    print "serving HTTP on", sa[0],  "port", sa[1], "..."
    httpd.serve_forever()

def test(HandlerClass = AuthHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    BaseHTTPServer.test(HandlerClass, ServerClass)


def main (mode, port):
    if mode == "http":
        test()
    elif mode == "https":
        sslWrap(port)
    else:
        print "invalid input"

if len(sys.argv)<4:
    print "usage serverr.py [port] [username:password] [mode]"
    sys.exit()

port = int(sys.argv[1])
key = base64.b64encode(sys.argv[2])
mode = str(sys.argv[3])
main(mode, port)