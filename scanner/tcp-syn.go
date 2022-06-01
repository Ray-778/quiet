package scanner

import (
	"net"
	"time"

	"quiet/vars"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCP syn
// return open ip:port
func TcpSYN(srcIp net.IP, srcPort int, dstIp string, dstPort int) (string, int, error) {
	// func LookupIP(host string) ([]IP, error)
	// LookupIP looks up host using the local resolver.
	// It returns a slice of that host's IPv4 and IPv6 addresses.
	// examples:
	// iprecords, _ := net.LookupIP("baidu.com")
	// for _, ip := range iprecords {
	// 	fmt.Println(ip)
	// }
	// print:
	// 220.181.38.251
	// 220.181.38.148
	dstAddrs, err := net.LookupIP(dstIp)
	if err != nil {
		return dstIp, 0, err
	}
	// func (ip IP) To4() IP
	// To4 converts the IPv4 address ip to a 4-byte representation.
	// If ip is not an IPv4 address, To4 returns nil.
	dstip := dstAddrs[0].To4()
	// // ParseIP parses s as an IP address, returning the result.
	// // string -> net.IP
	// srcip := net.ParseIP(srcIp)
	srcip := srcIp

	// Our port
	var (
		dstport layers.TCPPort = layers.TCPPort(dstPort)
		srcport layers.TCPPort = layers.TCPPort(srcPort)
	)

	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		SYN:     true,
	}

	// Our IP header
	// not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}

	// func (i *TCP) SetNetworkLayerForChecksum(l gopacket.NetworkLayer) error
	// SetNetworkLayerForChecksum tells this layer which network layer is wrapping it.
	// This is needed for computing the checksum when serializing,
	// since TCP/IP transport layer checksums depends on fields
	// in the IPv4 or IPv6 layer that contains it.
	// The passed in layer must be an *IPv4 or *IPv6.
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return dstIp, 0, err
	}

	// SerializeBuffer
	// NewSerializeBuffer creates a new instance
	// of the default implementation of the SerializeBuffer interface.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		// FixLengths determines whether, during serialization, layers should fix
		// the values for any length field that depends on the payload.
		FixLengths: true,
		// ComputeChecksums determines whether, during serialization,
		// layers should recompute checksums based on their payloads.
		ComputeChecksums: true,
	}

	// SerializeLayers clears the given write buffer,
	// then writes all layers into it so they correctly wrap each other.
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return dstIp, 0, err
	}

	// listen on local TCP connection
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return dstIp, 0, err
	}
	defer conn.Close()

	// send TCP SYN packet
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return dstIp, 0, err
	}
	// Set deadline so we do not wait forever.
	if err := conn.SetDeadline(time.Now().Add(time.Duration(vars.Timeout) * time.Second)); err != nil {
		return dstIp, 0, err
	}

	for {
		b := make([]byte, 4096)
		// func (c *IPConn) ReadFrom(b []byte) (int, Addr, error)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return dstIp, 0, err
		} else if addr.String() == dstip.String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.SrcPort == dstport {
					if tcp.SYN && tcp.ACK {
						return dstIp, dstPort, err
					} else {
						return dstIp, 0, err
					}
				}
			}
		}
	}

}
