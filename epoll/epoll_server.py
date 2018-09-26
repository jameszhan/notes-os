import socket
import select

EOL1 = b'\n\n'
EOL2 = b'\n\r\n'

response = b'HTTP/1.0 200 OK\r\nDate: Thu, 1 Jan 1970 00:00:00 GMT\r\n'
response += b'Content-Type: text/plain\r\nContent-Length: 13\r\n\r\n'
response += b'Hello, world!'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 5000))
server_socket.listen(1)
server_socket.setblocking(0)

print("EPOLLIN:\t{}".format(select.EPOLLIN))
print("EPOLLPRI:\t{}".format(select.EPOLLPRI))
print("EPOLLOUT:\t{}".format(select.EPOLLOUT))
print("EPOLLERR:\t{}".format(select.EPOLLERR))
print("EPOLLHUP:\t{}".format(select.EPOLLHUP))

epoll = select.epoll()
epoll.register(server_socket.fileno(), select.EPOLLIN)

print("ServerSocket fd: {}".format(server_socket.fileno()))

try:
    connections = {}
    requests = {}
    responses = {}

    while True:
        events = epoll.poll(1)
        for fd, event in events:
            print("fd: {}, event: {}".format(fd, event))
            if fd == server_socket.fileno():
                connection, address = server_socket.accept()
                connection.setblocking(0)
                epoll.register(connection.fileno(), select.EPOLLIN)
                print('epoll register {} with {}'.format(connection.fileno(), select.EPOLLIN))
                connections[connection.fileno()] = connection
                requests[connection.fileno()] = b''
                responses[connection.fileno()] = response
            elif event & select.EPOLLIN:
                requests[fd] += connections[fd].recv(1024)
                if EOL1 in requests[fd] or EOL2 in requests[fd]:
                    epoll.modify(fd, select.EPOLLOUT)
                    print('-'*40 + '\n' + requests[fd].decode()[:-2])
            elif event & select.EPOLLOUT:
                bytes_written = connections[fd].send(responses[fd])
                responses[fd] = responses[fd][bytes_written:]
                if len(responses[fd]) == 0:
                    epoll.modify(fd, 0)
                    connections[fd].shutdown(socket.SHUT_RDWR)
            elif event & select.EPOLLHUP:
                epoll.unregister(fd)
                connections[fd].close()
                del connections[fd]
finally:
    epoll.unregister(server_socket.fileno())
    epoll.close()
    server_socket.close()
