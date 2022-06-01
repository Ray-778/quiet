package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"quiet/util"
	"quiet/vars"
)

// ICMP header
type ICMP struct {
	Type           uint8
	Code           uint8
	Checksum       uint16
	Identification uint16
	Sequence       uint16
}

// Calculate checksum
func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return uint16(^sum)
}

// ICMP scan
func IcmpScan(host string) (string, error) {
	// icmp packet header
	var icmp ICMP
	icmp.Type = 8                          // 8->echo request;0->echo reply;
	icmp.Code = 0                          // request/reply message,code default 0
	icmp.Checksum = 0                      // checksum
	icmp.Identification = util.RandomNum() // identification
	icmp.Sequence = util.RandomNum()       // sequence number

	buf := new(bytes.Buffer)
	// func Write(w io.Writer, order ByteOrder, data interface{}) error
	// Writes the binary representation of data into w.
	binary.Write(buf, binary.BigEndian, icmp)
	// calculate checksum
	icmp.Checksum = CheckSum(buf.Bytes())
	// Reset buffer
	buf.Reset()

	// After checksum,
	// rewrites the binary representation of data (icmp) into buffer.
	binary.Write(buf, binary.BigEndian, icmp)

	// ip4:icmp
	conn, err := net.DialTimeout("ip4:icmp", fmt.Sprintf("%v", host), 2*time.Second)
	if err != nil {
		return "nil", err
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	// Set deadline so we do not wait forever.
	if err := conn.SetDeadline(time.Now().Add(time.Duration(vars.Timeout) * time.Second)); err != nil {
		return "nil", err
	}

	// send icmp request packet
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return "nil", err
	}

	// request 8 + reply 20 = 28
	var receive = make([]byte, 28)
	if n, err := conn.Read(receive); err != nil {
		return "nil", err
	} else if uint16(receive[24])<<8+uint16(receive[25]) != icmp.Identification &&
		uint16(receive[26])<<8+uint16(receive[27]) != icmp.Sequence {
		return "nil", err
	} else {
		_ = n
		return host, err
	}
}

// icmp scan task
func ICMPScanTask(taskChan chan string, wg *sync.WaitGroup) {
	for task := range taskChan {
		PrintICMPResult(IcmpScan(task))
		wg.Done()
	}
}

// Run icmp scan task
func RunICMPTask(tasks []string) {
	wg := &sync.WaitGroup{}

	// Create a channel which buffer is vars.threadNum * 2
	taskChan := make(chan string, vars.ThreadNum*2)

	// Create vars.ThreadNum coroutines
	for i := 0; i < vars.ThreadNum; i++ {
		go ICMPScanTask(taskChan, wg)
	}

	// The producer keeps sending data to taskChan until taskChan blocks.
	// The coroutine is first created,
	// then communicated with and transmitted to the coroutine
	for _, task := range tasks {
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()
}

// Save port scan result
func PrintICMPResult(ip string, err error) error {
	if err != nil {
		return err
	}
	if ip != "nil" {
		log.Printf("ICMP found host: %s", ip)
	}
	return err
}
