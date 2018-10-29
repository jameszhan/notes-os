import socket
import select
import os

from session import Session

class Reactor(object):

    def __init__(self, port, handle):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(1)
        server_socket.setblocking(0)
        self.server_socket = server_socket
        self.handle = handle

    def start(self):
        epoll = select.epoll()
        epoll.register(self.server_socket.fileno(), select.EPOLLIN)
        try:
            connections = {}
            while True:
                events = epoll.poll(1)
                for fd, event in events:
                    print("fd: {}, event: {}".format(fd, event))
                    if fd == self.server_socket.fileno():
                        connection, address = self.server_socket.accept()
                        connection.setblocking(0)
                        epoll.register(connection.fileno(), select.EPOLLIN)
                        connections[connection.fileno()] = Session(epoll, connection)
                    elif event & select.EPOLLIN:
                        session = connections[fd]
                        request = session.read()
                        if len(request) > 0:
                            child_pid = os.fork()
                            if child_pid == 0:
                                self.handle(session, request)
                            else:
                                print("fork {} to handle request {}.".format(child_pid, request))
                                os.waitpid(child_pid, 0)
                        else:
                            session.close()
                    elif event & select.EPOLLOUT:
                        connections[fd].send()
                    elif event & select.EPOLLHUP:
                        epoll.unregister(fd)
                        connections[fd].close()
                        del connections[fd]
        finally:
            epoll.unregister(self.server_socket.fileno())
            epoll.close()
            self.server_socket.close()


if __name__ == '__main__':
    reactor = Reactor(5000, lambda session, request: session.write(request))
    reactor.start()