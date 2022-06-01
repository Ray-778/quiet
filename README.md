# quiet

安全人员渗透测试工具

## 编译

```linux
go build -o quiet
```

## 功能

```
portscan, ps, p, port			tcp syn/connect port scanner
ICMPscan, icmpscan, is, ping	ICMP scanner
```

### 端口扫描（TCP-Connect 与 TCP-SYN）

参数

```
--concurrency value, -c value         concurrency (default: 1000)
--iplist value, --ip value, -i value  ip list
--local, -l                           local port scan (default: false)
--mode value, -m value                port scan mode
--port value, -p value                port list
--timeout value, -t value             timeout (default: 2)
```

使用格式

```
./quiet ps --iplist ip_list --port port_list --mode syn  --timeout 2 --concurrency 10
```

ip_list 支持格式：

```
1.1.1.1,1.1.1.1-255,1.1.1.*,1.1.1.1/24
```

port_list 支持格式：

```
1,2,3,4-5
```

未指定 port 则默认扫描以下常见端口

```
61616, 50070, 50000, 37777, 27017, 11211, 9999, 9418, 9200, 9100, 9092, 9042, 9001, 9000, 8686, 8545, 8443, 8081, 8080, 7077, 7001, 6379, 6000, 5984, 5938, 5900, 5672, 5601, 5555, 5432, 5222, 5000, 4730, 3389, 3306, 3128, 2379, 2375, 2181, 2049, 1883, 1521, 1433, 1099, 1080, 902, 873, 636, 623, 548, 515, 500, 465, 445, 443, 389, 139, 135, 123, 111, 110, 80, 53, 25, 23, 22, 21
```

mode 支持模式

```
--mode syn	// syn 模式需以 root 权限执行
--mode tcp
```

使用示例

普通扫描：

```
sudo ./quiet ps -i 114.114.114.110-120 -m syn -p 50-55,80 -c 100
```

![image-20220601160135806](image/image-20220601160135806.png)

内网端口：

内网端口扫描加入参数 --local/-l 则无需指定 ip 

```
sudo ./quiet ps -l -m syn -p 3300-3350 -c 20
```

![image-20220601160452202](image/image-20220601160452202.png)

### 主机探测（ICMP）

参数

```
--concurrency value, -c value         concurrency (default: 1000)
--domain value, -d value              domain
--iplist value, --ip value, -i value  ip list
--local, -l                           local ICMP scan (default: false)
--timeout value, -t value             timeout (default: 2)
```

使用格式

```
./quiet ping --iplist ip_list --timeout 2 --concurrency 10
./quiet ping --domain domain --timeout 2 --concurrency 10
```

ip_list 支持格式：

```
1.1.1.1,1.1.1.1-255,1.1.1.*,1.1.1.1/24
```

domain 直接输入域名

指定参数 --local/-l 则默认扫描内网 C 段

注意：ICMP 探测需 root 权限

使用示例

普通扫描：

```
sudo ./quiet ping -i 220.181.38.251/24
```

![image-20220601162201553](image/image-20220601162201553.png)

```
sudo ./main ping -d baidu.com
```

![image-20220601162058179](image/image-20220601162058179.png)

内网探测：

```
sudo ./quiet ping -l 
```

![image-20220601162337024](image/image-20220601162337024.png)

## 备注

本项目为本人Go语言学习产物，既有独立研究，亦有二次开发。
