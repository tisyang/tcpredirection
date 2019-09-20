# tcpredirection
A tcp server redirect clients to another tcp server written in c and libev.

基于 c 和 libev 编写的 TCP 端口转发服务器。

`tcpredirection` is a tcp server that accept some ports connections and make some connections to remote server, transmit data between clients and remote server.

`tcpredirection` 是一个 TCP 服务端程序，它接受本地端口的入站连接，同时创建到远程服务器端口的连接，并交换客户端和远程服务器间的数据通信。

## Usage 使用

`tcpredirection` use two text files in current working direction, `ip.txt` for in-comming clients ip whitelist filter, `tr.txt` for redirection rules.

Every line in `ip.txt` should contain a ip address that match client's peer ip which be allowed in-comming.

Every line in `tr.txt` should using format 'port remote_ip remote_port' (for example '8000 192.168.0.111 8000'), `port` is the port will listen on, `remote_ip` and `remote_port` is the target host and port which will redirect to.

`tcpredirction` 使用当前工作目录的两个文本文件：`ip.txt` 文件保存了连接本机的客户端IP的过滤列表；`tr.txt` 保存了端口转发规则。

`ip.txt` 每行文件应该包含一个允许连接本机的客户端IP地址。

`tr.txt` 每行的格式应该如 "本地端口 远程主机地址 远程主机端口" (例如 '8000 192.168.0.111 8000')，本地端口是程序将监听的端口，远程在主机地址和远程主机端口则是将转发到的目的地。

## Notes 注意事项

1. `tcpredirection` will cache size limited client's in-comming data before remote connection complete, the limit size is 1KB (you can modify it in source code). This is useful for some protocol like ntrip.

`tcpredirection` 会缓存一定长度的客户端发送来的数据，直到转发的远程连接完成再进行写入，缓存限制大小是 1KB，可以在代码中进行修改。这个特性适合类似 ntrip 协议的某些协议。

2. `tr.txt` 's remote address can use domains, but it will blocking the program when resolving. Use ip address make better performance.

`tr.txt` 中的远程地址可以使用域名，但是需要注意的是在解析域名的时候会阻塞程序。使用 IP 地址可以获得更好的性能。


