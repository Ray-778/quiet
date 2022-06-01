package scanner

import (
	"fmt"
	"net"
	"time"
)

// TCP connection
// return open ip:port
func TcpConnect(ip string, port int) (string, int, error) {
	// func DialTimeout(network, address string, timeout time.Duration) (Conn, error)
	// func Sprintf(format string, a ...interface{}) string
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), 2*time.Second)

	// If the connection was established successfully,
	// disconnect the connection at the end.
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	// If the connection was established successfully,
	// return ip, port
	return ip, port, err
}
