// #nosec G404: random number generator not used for security purposes
package ofctrl

import (
	"encoding/binary"
	"math/rand"
	"net"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
)

type PacketOut struct {
	InPort  uint32
	OutPort uint32
	Actions []OFAction

	SrcMAC     net.HardwareAddr
	DstMAC     net.HardwareAddr
	IPHeader   *protocol.IPv4
	IPv6Header *protocol.IPv6
	TCPHeader  *protocol.TCP
	UDPHeader  *protocol.UDP
	ICMPHeader *protocol.ICMP

	ARPHeader *protocol.ARP

	// EthernetPacket provides a convenient way to fill an Ethernet packet into
	// openflow15.PacketOut. User could either directly provide an Ethernet packet
	// using this field or filling L2/3/4 headers and fields above, then an Ethernet
	// packet will be generated accordingly and added to openflow15.PacketOut.
	EthernetPacket *protocol.Ethernet
}

func (p *PacketOut) GetMessage() util.Message {
	packetOut := openflow15.NewPacketOut()

	var inPort uint32
	if p.InPort != 0 {
		inPort = p.InPort
	} else {
		inPort = openflow15.P_CONTROLLER
	}

	packetOut.Match = *openflow15.NewMatch()
	inportField := openflow15.NewInPortField(inPort)
	packetOut.Match.AddField(*inportField)

	for _, act := range p.Actions {
		packetOut.AddAction(act.GetActionMessage())
	}
	packetOut.Data = p.getEthernetPacket()
	if p.OutPort > 0 {
		packetOut.AddAction(openflow15.NewActionOutput(p.OutPort))
	} else {
		packetOut.AddAction(openflow15.NewActionOutput(openflow15.P_TABLE))
	}
	return packetOut
}

// getEthernetPacket generates an Ethernet packet. If EthernetPacket is provided,
// return it directly. Otherwise, generate an Ethernet packet based on provided
// L2/3/4 fields, namely SrcMAC, DstMAC, IPHeader, IPv6Header, TCPHeader,
// UDPHeader, ICMPHeader and ARPHeader.
func (p *PacketOut) getEthernetPacket() util.Message {
	if p.EthernetPacket != nil {
		return p.EthernetPacket
	}
	ethPkt := &protocol.Ethernet{
		HWDst: p.DstMAC,
		HWSrc: p.SrcMAC,
	}

	var data util.Message
	var ethType uint16
	if p.ARPHeader != nil {
		data = p.ARPHeader
		ethType = 0x0806
	} else if p.IPv6Header != nil {
		switch {
		case p.TCPHeader != nil:
			p.IPv6Header.NextHeader = protocol.Type_TCP
			p.IPv6Header.Data = p.TCPHeader
		case p.UDPHeader != nil:
			p.IPv6Header.NextHeader = protocol.Type_UDP
			p.IPv6Header.Data = p.UDPHeader
		case p.ICMPHeader != nil:
			p.IPv6Header.NextHeader = protocol.Type_IPv6ICMP
			p.IPv6Header.Data = p.ICMPHeader
		}
		// Let application set IPv6Header.Data and IPv6Header.NextHeader for other IPv6 packets.
		data = p.IPv6Header
		ethType = protocol.IPv6_MSG
	} else {
		switch {
		case p.TCPHeader != nil:
			p.IPHeader.Protocol = protocol.Type_TCP
			p.IPHeader.Data = p.TCPHeader
		case p.UDPHeader != nil:
			p.IPHeader.Protocol = protocol.Type_UDP
			p.IPHeader.Data = p.UDPHeader
		case p.ICMPHeader != nil:
			p.IPHeader.Protocol = protocol.Type_ICMP
			p.IPHeader.Data = p.ICMPHeader
		}
		// Let application set IPHeader.Data and IPHeader.Protocol for other IPv4 packets.
		data = p.IPHeader
		ethType = 0x0800
	}
	ethPkt.Ethertype = ethType
	ethPkt.Data = data
	return ethPkt
}

func (p *PacketIn) GetMatches() *Matchers {
	matches := make([]*MatchField, 0, len(p.Match.Fields))
	for i := range p.Match.Fields {
		matches = append(matches, NewMatchField(&p.Match.Fields[i]))
	}
	return &Matchers{matches: matches}
}

func GenerateTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort, srcPort uint16, tcpFlags *uint8) *PacketOut {
	tcpHeader := GenerateTCPHeader(dstPort, srcPort, tcpFlags)
	var pktOut *PacketOut
	if srcIP.To4() == nil {
		ipv6Header := &protocol.IPv6{
			Version:    6,
			Length:     tcpHeader.Len(),
			HopLimit:   64,
			NextHeader: protocol.Type_TCP,
			NWSrc:      srcIP,
			NWDst:      dstIP,
		}
		pktOut = &PacketOut{
			SrcMAC:     srcMAC,
			DstMAC:     dstMAC,
			IPv6Header: ipv6Header,
			TCPHeader:  tcpHeader,
		}
	} else {
		ipHeader := &protocol.IPv4{
			Version:        4,
			IHL:            5,
			Length:         20 + tcpHeader.Len(),
			Id:             uint16(rand.Int()),
			Flags:          0,
			FragmentOffset: 0,
			TTL:            64,
			Protocol:       protocol.Type_TCP,
			Checksum:       0,
			NWSrc:          srcIP,
			NWDst:          dstIP,
		}
		pktOut = &PacketOut{
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			IPHeader:  ipHeader,
			TCPHeader: tcpHeader,
		}
	}

	return pktOut
}

func GenerateSimpleIPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) *PacketOut {
	icmpHeader := GenerateICMPHeader(nil, nil)
	ipHeader := &protocol.IPv4{
		Version:        4,
		IHL:            5,
		Length:         20 + icmpHeader.Len(),
		Id:             uint16(rand.Int()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       protocol.Type_ICMP,
		Checksum:       0,
		NWSrc:          srcIP,
		NWDst:          dstIP,
	}
	pktOut := &PacketOut{
		SrcMAC:     srcMAC,
		DstMAC:     dstMAC,
		IPHeader:   ipHeader,
		ICMPHeader: icmpHeader,
	}
	return pktOut
}

func GenerateTCPHeader(dstPort, srcPort uint16, flags *uint8) *protocol.TCP {
	header := protocol.NewTCP()
	if dstPort != 0 {
		header.PortDst = dstPort
	} else {
		header.PortDst = uint16(rand.Uint32())
	}
	if srcPort != 0 {
		header.PortSrc = srcPort
	} else {
		header.PortSrc = uint16(rand.Uint32())
	}
	header.AckNum = rand.Uint32()
	header.AckNum = header.AckNum + 1
	header.HdrLen = 20
	if flags != nil {
		header.Code = *flags
	} else {
		header.Code = uint8(1 << 1)
	}
	return header
}

func GenerateICMPHeader(icmpType, icmpCode *uint8) *protocol.ICMP {
	header := protocol.NewICMP()
	if icmpType != nil {
		header.Type = *icmpType
	} else {
		header.Type = 8
	}
	if icmpCode != nil {
		header.Code = *icmpCode
	} else {
		header.Code = 0
	}
	identifier := uint16(rand.Uint32())
	seq := uint16(1)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data, identifier)
	binary.BigEndian.PutUint16(data[2:], seq)
	return header
}
