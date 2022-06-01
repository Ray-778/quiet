package vars

import (
	"net"
	"sync"
)

var (
	Timeout   = 2
	ThreadNum = 1000
)

var (
	PortScanResult *sync.Map
	SrcIP          net.IP
	Host           string

	Port    = []int{61616, 50070, 50000, 37777, 27017, 11211, 9999, 9418, 9200, 9100, 9092, 9042, 9001, 9000, 8686, 8545, 8443, 8081, 8080, 7077, 7001, 6379, 6000, 5984, 5938, 5900, 5672, 5601, 5555, 5432, 5222, 5000, 4730, 3389, 3306, 3128, 2379, 2375, 2181, 2049, 1883, 1521, 1433, 1099, 1080, 902, 873, 636, 623, 548, 515, 500, 465, 445, 443, 389, 139, 135, 123, 111, 110, 80, 53, 25, 23, 22, 21}
	SrcPort = 30274

	PortScanMode     = "tcp"
	ModeFlag         = "TCP connection mode"
	UseToTestLocalIP = "114.114.114.114"
)

var (
	ICMPHost = []string{}
)

func init() {
	PortScanResult = &sync.Map{}
}
