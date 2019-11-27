import socket
import select

EOL1 = b'\n\n'
EOL2 = b'\n\r\n'

response = (
    'HTTP/1.1 200 OK\r\n'
    'Date: Thu, 1 Jan 1970 00:00:00 GMT\r\n'
    'Content-Type: text/plain\r\n'
    'Content-Length: 13\r\n'
    '\r\n'
    'Hello, World!'
).encode('iso8859-1')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 5000))
server_socket.listen(1)
server_socket.setblocking(False)

print("ServerSocket fd: {}".format(server_socket.fileno()))

try:
    rlist, wlist, xlist = [server_socket], [], []
    while True:
        rs, ws, xs = select.select(rlist, wlist, xlist)

        for r in rs:
            if r is server_socket:
                connection, address = server_socket.accept()
                connection.setblocking(False)
                rlist.append(connection)
            else:
                data = r.recv(1024)
                if EOL1 in data or EOL2 in data:
                    print('-' * 40 + '\n' + data.decode()[:-2])
                    wlist.append(r)

        for w in ws:
            bytes_written = w.send(response)
            if bytes_written == len(response):
                wlist.remove(w)
                w.shutdown(socket.SHUT_RDWR)
            else:
                print("Write {} with len {} but response len is {}.".format(w.fileno(), bytes_written, len(response)))

        for x in xs:
            if x in wlist:
                wlist.remove(x)
            rlist.remove(x)
finally:
    server_socket.close()
