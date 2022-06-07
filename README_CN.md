# vtun

一款简单易用的VPN，基于Go语言开发。

[EN](https://github.com/net-byte/vtun/blob/master/README.md) | [中文](https://github.com/net-byte/vtun/blob/master/README_CN.md)

[![Travis](https://travis-ci.com/net-byte/vtun.svg?branch=master)](https://github.com/net-byte/vtun)
[![Go Report Card](https://goreportcard.com/badge/github.com/net-byte/vtun)](https://goreportcard.com/report/github.com/net-byte/vtun)
![image](https://img.shields.io/badge/License-MIT-orange)
![image](https://img.shields.io/badge/License-Anti--996-red)
![image](https://img.shields.io/github/downloads/net-byte/vtun/total.svg)

# 特性
* 支持udp
* 支持websocket
* 支持tls
* 支持grpc
* 支持kcp

# 用法

```
Usage of ./vtun:
  -S    server mode
  -c string
        tun interface cidr (default "172.16.0.10/24")
  -c6 string
        tun interface ipv6 cidr (default "fced:9999::9999/64")
  -certificate string
        tls certificate file path (default "./certs/server.pem")
  -privatekey string
        tls certificate key file path (default "./certs/server.key")
  -sni string
        tls handshake sni
  -isv
        tls insecure skip verify
  -dn string
        device name
  -g    client global mode
  -k string
        key (default "freedom@2022")
  -l string
        local address (default ":3000")
  -mtu int
        tun mtu (default 1500)
  -obfs
        enable data obfuscation
  -p string
        protocol udp/kcp/tls/grpc/ws/wss (default "udp")
  -path string
        websocket path (default "/freedom")
  -s string
        server address (default ":3001")
  -sip string
        intranet server ip (default "172.16.0.1")
  -sip6 string
        intranet server ipv6 (default "fced:9999::1")
  -dip string
        dns server ip (default "8.8.8.8")
  -t int
        dial timeout in seconds (default 30)
```

## 编译

```
sh scripts/build.sh
```

## Linux客户端

```
sudo ./vtun-linux-amd64 -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456

```

## Linux全局模式客户端（转发所有流量）

```
sudo ./vtun-linux-amd64 -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456 -g

```
## MacOS客户端

```
sudo ./vtun-darwin-amd64 -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456 -g -sip 172.16.0.1

```

## Linux服务端

```
sudo ./vtun-linux-amd64 -S -l :3001 -c 172.16.0.1/24 -k 123456

```

## 在Linux上设置iptables

```
  # 设置ipv4和ipv6流量转发
  vi /etc/sysctl.conf
  net.ipv4.ip_forward = 1
  net.ipv6.conf.all.forwarding=1
  net.core.rmem_max=26214400
  net.core.rmem_default=26214400
  net.core.wmem_max=26214400
  net.core.wmem_default=26214400
  net.core.netdev_max_backlog=2048
  sysctl -p /etc/sysctl.conf
  # 设置NAT转发流量
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
  iptables -A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A FORWARD -j ACCEPT
```

## Docker
[镜像](https://hub.docker.com/r/netbyte/vtun)

### 运行客户端
```
docker run  -d --privileged --restart=always --net=host --name vtun-client \
netbyte/vtun -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456
```

### 运行全局模式客户端
```
docker run  -d --privileged --restart=always --net=host --name vtun-client \
netbyte/vtun -l :3000 -s server-addr:3001 -c 172.16.0.10/24 -k 123456 -g
```

### 运行服务端
```
docker run  -d --privileged --restart=always --net=host --name vtun-server \
netbyte/vtun -S -l :3001 -c 172.16.0.1/24 -k 123456
```

## 移动端

### [Android](https://github.com/net-byte/vTunnel)

## TODO
1. 支持Windows
2. 开发iOS应用

# License
[The MIT License (MIT)](https://raw.githubusercontent.com/net-byte/vtun/master/LICENSE)
