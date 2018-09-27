import socket

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

try:
    while True:
        client, address = server_socket.accept()
        request = b''
        while EOL1 not in request and EOL2 not in request:
            request += client.recv(1024)
        print('-' * 40 + '\n' + request.decode()[:-2])
        client.send(response)
        client.close()
finally:
    server_socket.close()
