# Netcat 札记

## 端口监听

### 查询 HTTP 请求内容

先启动监听

```bash
nc -l 6666
```

再发送请求

```bash
curl -iv0 -X POST -d '{"name":"James Zhan","age":13}' http://127.0.0.1:6666/api/users/ --header "Content-Type:application/json"
```

这是可以在监听的窗口捕获到所有 HTTP 请求信息

### 传输文件

```bash
# 启动监听
nc -d -l 6666 > /tmp/create-user.out 
```

```
# 传输文件
nc 127.0.0.1 6666 < create-user.in
```

```bash
cat /tmp/create-user.out 
```

### 实时通讯工具

启动监听

```bash
nc -d -l 6666
```

联机

````bash
nc -n 127.0.0.1 6666
````

这时，可以很方便地把客户端输入的文本内容同步到监听端

## 端口扫描

### TCP 端口扫描

```bash
nc -v -z -w2 127.0.0.1 8000-9000
``` 
### UDP 端口扫描

```bash
nc -u -v -z -w2 127.0.0.1 1-9999 
```

## 用作 Http Client

### POST

```bash
echo -n 'POST /api/users HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{"name":"James Zhan","age":13}' | nc 127.0.0.1 8080
echo -n 'POST /api/users HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{"name":"James Zhan","age":13}' | nc 127.0.0.1 8080

nc 127.0.0.1 8080 < create-user.in

nc 127.0.0.1 8080 << EOF
POST /api/users HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json
Content-Length: 30

{"name":"James Zhan","age":13}
EOF
```

等价于

```bash
curl -iv -X POST -d '{"name":"James Zhan","age":13}' http://127.0.0.1:8080/api/users/ --header "Content-Type:application/json"
```

### GET

```bash
echo -n 'GET /api/users HTTP/1.0\r\n\r\n' | nc 127.0.0.1 8080
echo -n 'GET /api/users/5 HTTP/1.0\r\n\r\n' | nc 127.0.0.1 8080
```

等价于

```bash
curl -iv http://127.0.0.1:8080/api/users
curl -iv http://127.0.0.1:8080/api/users/5
```

### PUT / PATCH

```bash
echo -n 'PATCH /api/users/5 HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{"name":"James Zhan","age":18}' | nc 127.0.0.1 8080
nc 127.0.0.1 8080 < update-user.in

nc 127.0.0.1 8080 << EOF
PUT /api/users/5 HTTP/1.0
Content-Type: application/json
Content-Length: 30

{"name":"James Zhan","age":18}
EOF
```

```bash
curl -iv -X PUT -d '{"name":"James Zhan","age":18}' http://127.0.0.1:8080/api/users/5 --header "Content-Type:application/json"
```
 
### DELETE

```bash
echo -n 'DELETE /api/users/5 HTTP/1.0\r\n\r\n' | nc 127.0.0.1 8080
```

等价于

```bash
curl -iv -X DELETE http://127.0.0.1:8080/api/users/5
```


## 收集服务器统计信息

### 检查 Zookeeper 状态

```bash
echo 'stats' | nc 127.0.0.1 2181

nc 127.0.0.1 2183 << EOF
stats
EOF
```




