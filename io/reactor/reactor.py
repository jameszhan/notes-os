import socket
import select
from session import Session

EOL1 = b'\n\n'
EOL2 = b'\n\r\n'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 5000))
server_socket.listen(1)
server_socket.setblocking(0)

epoll = select.epoll()
epoll.register(server_socket.fileno(), select.EPOLLIN)

try:
    connections = {}
    while True:
        events = epoll.poll(1)
        for fd, event in events:
            print("fd: {}, event: {}".format(fd, event))
            if fd == server_socket.fileno():
                connection, address = server_socket.accept()
                connection.setblocking(0)
                epoll.register(connection.fileno(), select.EPOLLIN)
                connections[connection.fileno()] = Session(epoll, connection)
            elif event & select.EPOLLIN:
                session = connections[fd]
                request = session.read()
                if len(request) > 0:
                    session.write(request)
                else:
                    session.close()
            elif event & select.EPOLLOUT:
                connections[fd].send()
            elif event & select.EPOLLHUP:
                epoll.unregister(fd)
                connections[fd].close()
                del connections[fd]
finally:
    epoll.unregister(server_socket.fileno())
    epoll.close()
    server_socket.close()
