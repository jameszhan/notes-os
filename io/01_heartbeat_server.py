import socket
import threading
import time

CHECK_TIMEOUT = 15
BUF_SIZE = 4096


class Heartbeats(object):

    def __init__(self):
        self._clients = {}
        self._lock = threading.Lock()

    def __setitem__(self, key, value):
        self._lock.acquire()
        try:
            self._clients.__setitem__(key, value)
        finally:
            self._lock.release()

    def getsilents(self):
        threshold = time.time() - CHECK_TIMEOUT
        self._lock.acquire()
        try:
            return [ip for (ip, lastTime) in self._clients.items() if lastTime < threshold]
        finally:
            self._lock.release()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 5000))
server_socket.listen(10)

try:
    heartbeats = Heartbeats()

    while True:
        conn, address = server_socket.accept()
        ping = conn.recv(4096)
        ip = conn.getpeername()
        print("{}: {}".format(ip, ping))
        heartbeats[ip] = time.time()

        print("Silents: {}".format(heartbeats.getsilents()))
finally:
    server_socket.close()
