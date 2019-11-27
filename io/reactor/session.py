import select
import queue


class Session(object):

    def __init__(self, epoll, socket):
        self.epoll = epoll
        self.socket = socket
        self.pending_writes = queue.Queue()

    def read(self):
        request = self.socket.recv(1024)
        print("received {}.".format(request))
        return request

    def send(self):
        if self.pending_writes.empty():
            self.epoll.modify(self.socket.fileno(), select.EPOLLIN)
        else:
            while not self.pending_writes.empty():
                value = self.pending_writes.get()
                self.socket.send(value)

    def write(self, response):
        self.pending_writes.put(response)
        print("send {}.".format(response))
        self.epoll.modify(self.socket.fileno(), select.EPOLLOUT)

    def close(self):
        self.socket.close()
