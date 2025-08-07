/*
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofctrl

// This file implements the forwarding graph API for the flow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	log "github.com/sirupsen/logrus"
)

// Small subset of openflow fields we currently support
type FlowMatch struct {
	Priority      uint16               // Priority of the flow
	InputPort     uint32               // Input port number
	MacDa         *net.HardwareAddr    // Mac dest
	MacDaMask     *net.HardwareAddr    // Mac dest mask
	MacSa         *net.HardwareAddr    // Mac source
	MacSaMask     *net.HardwareAddr    // Mac source mask
	Ethertype     uint16               // Ethertype
	NonVlan       bool                 // Non-vlan
	VlanId        *uint16              // vlan id
	VlanMask      *uint16              // Mask for vlan id
	ArpOper       uint16               // ARP Oper type
	ArpSha        *net.HardwareAddr    // ARP source host address
	ArpTha        *net.HardwareAddr    // ARP target host address
	ArpSpa        *net.IP              // ARP source protocol address
	ArpTpa        *net.IP              // ARP target protocol address
	IpSa          *net.IP              // IPv4 source addr
	IpSaMask      *net.IP              // IPv4 source mask
	IpDa          *net.IP              // IPv4 dest addr
	IpDaMask      *net.IP              // IPv4 dest mask
	CtIpSa        *net.IP              // IPv4 source addr in ct
	CtIpSaMask    *net.IP              // IPv4 source mask in ct
	CtIpDa        *net.IP              // IPv4 dest addr in ct
	CtIpDaMask    *net.IP              // IPv4 dest mask in ct
	CtIpv6Sa      *net.IP              // IPv6 source addr
	CtIpv6SaMask  *net.IP              // IPv6 source mask in ct
	CtIpv6Da      *net.IP              // IPv6 dest addr in ct
	CtIpv6DaMask  *net.IP              // IPv6 dest mask in ct
	IpProto       uint8                // IP protocol
	CtIpProto     uint8                // IP protocol in ct
	IpDscp        uint8                // DSCP/TOS field
	SrcPort       uint16               // Source port in transport layer
	SrcPortMask   *uint16              // Mask for source port in transport layer
	DstPort       uint16               // Dest port in transport layer
	DstPortMask   *uint16              // Mask for dest port in transport layer
	CtTpSrcPort   uint16               // Source port in the transport layer in ct
	CtTpDstPort   uint16               // Dest port in the transport layer in ct
	Icmp6Code     *uint8               // ICMPv6 code
	Icmp6Type     *uint8               // ICMPv6 type
	Icmp4Code     *uint8               // ICMPv4 code
	Icmp4Type     *uint8               // ICMPv4 type
	NdTarget      *net.IP              // ICMPv6 Neighbor Discovery Target
	NdTargetMask  *net.IP              // Mask for ICMPv6 Neighbor Discovery Target
	NdSll         *net.HardwareAddr    // ICMPv6 Neighbor Discovery Source Ethernet Address
	NdTll         *net.HardwareAddr    // ICMPv6 Neighbor DIscovery Target Ethernet Address
	IpTtl         *uint8               // IPV4 TTL
	Metadata      *uint64              // OVS metadata
	MetadataMask  *uint64              // Metadata mask
	TunnelId      uint64               // Vxlan Tunnel id i.e. VNI
	TunnelDst     *net.IP              // Tunnel destination addr
	TcpFlags      *uint16              // TCP flags
	TcpFlagsMask  *uint16              // Mask for TCP flags
	ConjunctionID *uint32              // Add AddConjunction ID
	CtStates      *openflow15.CTStates // Connection tracking states
	NxRegs        []*NXRegister        // regX or regX[m..n]
	XxRegs        []*XXRegister        // xxregN or xxRegN[m..n]
	CtMark        uint32               // conn_track mark
	CtMarkMask    *uint32              // Mask of conn_track mark
	CtLabelLo     uint64               // conntrack label [0..63]
	CtLabelHi     uint64               // conntrack label [64..127]
	CtLabelLoMask uint64               // conntrack label masks [0..63]
	CtLabelHiMask uint64               // conntrack label masks [64..127]
	ActsetOutput  uint32               // Output port number
	TunMetadatas  []*NXTunMetadata     // tun_metadataX or tun_metadataX[m..n]
	PktMark       uint32               // Packet mark
	PktMarkMask   *uint32              // Packet mark mask
}

// additional Actions in flow's instruction set
type FlowAction struct {
	ActionType    string           // Type of action "setVlan", "setMetadata"
	vlanId        uint16           // Vlan Id in case of "setVlan"
	macAddr       net.HardwareAddr // Mac address to set
	mplsEtherType uint16           // mpls ether type to push or pop
	ipAddr        net.IP           // IP address to be set
	l4Port        uint16           // Transport port to be set
	arpOper       uint16           // Arp operation type to be set
	tunnelId      uint64           // Tunnel Id (used for setting VNI)
	metadata      uint64           // Metadata in case of "setMetadata"
	metadataMask  uint64           // Metadata mask
	dscp          uint8            // DSCP field
	setFieldAct   *SetFieldAction  // SetField action
	copyFieldAct  *CopyFieldAction // CopyField action
	//TODO: remove following two actions.
	loadAct     *NXLoadAction        // Load data into OXM/NXM fields, one or more Actions
	moveAct     *NXMoveAction        // Move data from src OXM/NXM field to dst field
	conjunction *NXConjunctionAction // AddConjunction Actions to be set
	connTrack   *NXConnTrackAction   // ct Actions to be set
	resubmit    *Resubmit            // resubmit packet to a specific Table and port. Resubmit could also be a NextElem.
	// If the packet is resubmitted to multiple ports, use resubmit as a FlowAction
	// and the NextElem should be Empty.
	learn      *FlowLearn    // nxm learn action
	notes      []byte        // data to set in note action
	controller *NXController // send packet to controller
	nxOutput   *NXOutput     // output packet to a provided register
}

// State of a flow entry
type Flow struct {
	Table       *Table        // Table where this flow resides
	Match       FlowMatch     // Fields to be matched
	NextElem    FgraphElem    // Next fw graph element
	HardTimeout uint16        // Timeout to remove the flow after it is installed in the switch
	IdleTimeout uint16        // Timeout to remove the flow after its last hit
	isInstalled bool          // Is the flow installed in the switch
	CookieID    uint64        // Cookie ID for flowMod message
	CookieMask  *uint64       // Cookie Mask for flowMod message
	flowActions []*FlowAction // List of flow Actions
	lock        sync.RWMutex  // lock for modifying flow state
	statusLock  sync.RWMutex  // lock for modifying flow realized status
	realized    bool          // Realized status of flow

	appliedActions []OFAction
	writtenActions []OFAction
	metadata       *writeMetadata
	gotoTable      *uint8
	clearActions   bool
	meter          *uint32
}

type writeMetadata struct {
	data uint64
	mask uint64
}

// Matches data either exactly or with optional mask in register number ID. The mask
// could be calculated according to range automatically
type NXRegister struct {
	ID    int                 // ID of NXM_NX_REG, value should be from 0 to 15
	Data  uint32              // Data to cache in register. Note: Don't shift Data to its offset in caller
	Mask  uint32              // Bitwise mask of data
	Range *openflow15.NXRange // Range of bits in register
}

type XXRegister struct {
	ID   int    // ID of NXM_NX_XXREG, value should be from 0 to 3
	Data []byte // Data to cache in xxreg
}

type NXTunMetadata struct {
	ID    int                 // ID of NXM_NX_TUN_METADATA, value should be from 0 to 7. OVS supports 64 tun_metadata, but only 0-7 is implemented in libOpenflow
	Data  interface{}         // Data to set in the register
	Range *openflow15.NXRange // Range of bits in the field
}

const IP_PROTO_TCP = 6
const IP_PROTO_UDP = 17
const IP_PROTO_SCTP = 132

var (
	EmptyFlowActionError    = errors.New("flow Actions is empty")
	UnknownElementTypeError = errors.New("unknown Fgraph element type")
	UnknownActionTypeError  = errors.New("unknown action type")
)

type FlowBundleMessage struct {
	message *openflow15.FlowMod
}

func (m *FlowBundleMessage) resetXid(xid uint32) util.Message {
	m.message.Xid = xid
	log.Debugf("resetXid xid: %x", m.message.Xid)
	return m.message
}

func (m *FlowBundleMessage) getXid() uint32 {
	return m.message.Xid
}

func (m *FlowBundleMessage) GetMessage() util.Message {
	return m.message
}

// string key for the flow
// FIXME: simple json conversion for now. This needs to be smarter
func (f *Flow) flowKey() string {
	jsonVal, err := json.Marshal(f.Match)
	if err != nil {
		log.Errorf("Error forming flowkey for %+v. Err: %v", f, err)
		return ""
	}

	return string(jsonVal)
}

// Fgraph element type for the flow
func (f *Flow) Type() string {
	return "flow"
}

// instruction set for flow element
func (f *Flow) GetFlowInstr() openflow15.Instruction {
	log.Fatalf("Unexpected call to get flow's instruction set")
	return nil
}

// Translate our match fields into openflow 1.5 match fields
func (f *Flow) xlateMatch() openflow15.Match {
	ofMatch := openflow15.NewMatch()

	// Handle input port
	if f.Match.InputPort != 0 {
		inportField := openflow15.NewInPortField(f.Match.InputPort)
		ofMatch.AddField(*inportField)
	}

	// Handle MacDa field
	if f.Match.MacDa != nil {
		if f.Match.MacDaMask != nil {
			macDaField := openflow15.NewEthDstField(*f.Match.MacDa, f.Match.MacDaMask)
			ofMatch.AddField(*macDaField)
		} else {
			macDaField := openflow15.NewEthDstField(*f.Match.MacDa, nil)
			ofMatch.AddField(*macDaField)
		}
	}

	// Handle MacSa field
	if f.Match.MacSa != nil {
		if f.Match.MacSaMask != nil {
			macSaField := openflow15.NewEthSrcField(*f.Match.MacSa, f.Match.MacSaMask)
			ofMatch.AddField(*macSaField)
		} else {
			macSaField := openflow15.NewEthSrcField(*f.Match.MacSa, nil)
			ofMatch.AddField(*macSaField)
		}
	}

	// Handle ethertype
	if f.Match.Ethertype != 0 {
		etypeField := openflow15.NewEthTypeField(f.Match.Ethertype)
		ofMatch.AddField(*etypeField)
	}

	// Handle Vlan id
	if f.Match.NonVlan {
		vidField := openflow15.NewVlanIdField(0, nil)
		vidField.Value = new(openflow15.VlanIdField)
		ofMatch.AddField(*vidField)
	} else if f.Match.VlanId != nil {
		vidField := openflow15.NewVlanIdField(*f.Match.VlanId, f.Match.VlanMask)
		ofMatch.AddField(*vidField)
	}

	// Handle ARP Oper type
	if f.Match.ArpOper != 0 {
		arpOperField := openflow15.NewArpOperField(f.Match.ArpOper)
		ofMatch.AddField(*arpOperField)
	}

	// Handle ARP THA
	if f.Match.ArpTha != nil {
		arpTHAField := openflow15.NewArpThaField(*f.Match.ArpTha)
		ofMatch.AddField(*arpTHAField)
	}

	// Handle ARP SHA
	if f.Match.ArpSha != nil {
		arpSHAField := openflow15.NewArpShaField(*f.Match.ArpSha)
		ofMatch.AddField(*arpSHAField)
	}

	// Handle ARP TPA
	if f.Match.ArpTpa != nil {
		arpTPAField := openflow15.NewArpTpaField(*f.Match.ArpTpa)
		ofMatch.AddField(*arpTPAField)
	}

	// Handle ARP SPA
	if f.Match.ArpSpa != nil {
		arpSPAField := openflow15.NewArpSpaField(*f.Match.ArpSpa)
		ofMatch.AddField(*arpSPAField)
	}

	// Handle IP Dst
	if f.Match.IpDa != nil {
		if f.Match.IpDa.To4() != nil {
			ipDaField := openflow15.NewIpv4DstField(*f.Match.IpDa, f.Match.IpDaMask)
			ofMatch.AddField(*ipDaField)
		} else {
			ipv6DaField := openflow15.NewIpv6DstField(*f.Match.IpDa, f.Match.IpDaMask)
			ofMatch.AddField(*ipv6DaField)
		}
	}

	// Handle IP Src
	if f.Match.IpSa != nil {
		if f.Match.IpSa.To4() != nil {
			ipSaField := openflow15.NewIpv4SrcField(*f.Match.IpSa, f.Match.IpSaMask)
			ofMatch.AddField(*ipSaField)
		} else {
			ipv6SaField := openflow15.NewIpv6SrcField(*f.Match.IpSa, f.Match.IpSaMask)
			ofMatch.AddField(*ipv6SaField)
		}
	}

	// Handle IP protocol
	if f.Match.IpProto != 0 {
		protoField := openflow15.NewIpProtoField(f.Match.IpProto)
		ofMatch.AddField(*protoField)
	}

	// Handle IP dscp
	if f.Match.IpDscp != 0 {
		dscpField := openflow15.NewIpDscpField(f.Match.IpDscp, nil)
		ofMatch.AddField(*dscpField)
	}

	// Handle port numbers
	if f.Match.SrcPort != 0 {
		var portField *openflow15.MatchField
		switch f.Match.IpProto {
		case IP_PROTO_UDP:
			portField = openflow15.NewUdpSrcField(f.Match.SrcPort)
		case IP_PROTO_SCTP:
			portField = openflow15.NewSctpSrcField(f.Match.SrcPort)
		case IP_PROTO_TCP:
			fallthrough
		default:
			portField = openflow15.NewTcpSrcField(f.Match.SrcPort)
		}

		if f.Match.SrcPortMask != nil {
			portField.HasMask = true
			portMaskField := openflow15.NewPortField(*f.Match.SrcPortMask)
			portField.Mask = portMaskField
			portField.Length += uint8(portMaskField.Len())
		}
		ofMatch.AddField(*portField)
	}

	if f.Match.DstPort != 0 {
		var portField *openflow15.MatchField
		switch f.Match.IpProto {
		case IP_PROTO_UDP:
			portField = openflow15.NewUdpDstField(f.Match.DstPort)
		case IP_PROTO_SCTP:
			portField = openflow15.NewSctpDstField(f.Match.DstPort)
		case IP_PROTO_TCP:
			fallthrough
		default:
			portField = openflow15.NewTcpDstField(f.Match.DstPort)
		}
		if f.Match.DstPortMask != nil {
			portField.HasMask = true
			portMaskField := openflow15.NewPortField(*f.Match.DstPortMask)
			portField.Mask = portMaskField
			portField.Length += uint8(portMaskField.Len())
		}
		ofMatch.AddField(*portField)
	}

	// Handle tcp flags
	if f.Match.IpProto == IP_PROTO_TCP && f.Match.TcpFlags != nil {
		tcpFlagField := openflow15.NewTcpFlagsField(*f.Match.TcpFlags, f.Match.TcpFlagsMask)
		ofMatch.AddField(*tcpFlagField)
	}

	// Handle metadata
	if f.Match.Metadata != nil {
		if f.Match.MetadataMask != nil {
			metadataField := openflow15.NewMetadataField(*f.Match.Metadata, f.Match.MetadataMask)
			ofMatch.AddField(*metadataField)
		} else {
			metadataField := openflow15.NewMetadataField(*f.Match.Metadata, nil)
			ofMatch.AddField(*metadataField)
		}
	}

	// Handle Vxlan tunnel id
	if f.Match.TunnelId != 0 {
		tunnelIdField := openflow15.NewTunnelIdField(f.Match.TunnelId)
		ofMatch.AddField(*tunnelIdField)
	}

	// Handle IPv4 tunnel destination addr
	if f.Match.TunnelDst != nil {
		if ipv4Dst := f.Match.TunnelDst.To4(); ipv4Dst != nil {
			tunnelDstField := openflow15.NewTunnelIpv4DstField(ipv4Dst, nil)
			ofMatch.AddField(*tunnelDstField)
		} else {
			tunnelIpv6DstField := openflow15.NewTunnelIpv6DstField(*f.Match.TunnelDst, nil)
			ofMatch.AddField(*tunnelIpv6DstField)
		}
	}

	// Handle conjunction id
	if f.Match.ConjunctionID != nil {
		conjIDField := openflow15.NewConjIDMatchField(*f.Match.ConjunctionID)
		ofMatch.AddField(*conjIDField)
	}

	// Handle ct states
	if f.Match.CtStates != nil {
		ctStateField := openflow15.NewCTStateMatchField(f.Match.CtStates)
		ofMatch.AddField(*ctStateField)
	}

	// Handle reg match
	if f.Match.NxRegs != nil {
		regMap := make(map[int][]*NXRegister)
		for _, reg := range f.Match.NxRegs {
			_, found := regMap[reg.ID]
			if !found {
				regMap[reg.ID] = []*NXRegister{reg}
			} else {
				regMap[reg.ID] = append(regMap[reg.ID], reg)
			}
		}
		for _, regs := range regMap {
			reg := merge(regs)
			regField := openflow15.NewRegMatchFieldWithMask(reg.ID, reg.Data, reg.Mask)
			ofMatch.AddField(*regField)
		}
	}

	// Handle xxreg match
	if f.Match.XxRegs != nil {
		for _, reg := range f.Match.XxRegs {
			fieldName := fmt.Sprintf("NXM_NX_XXReg%d", reg.ID)
			field, _ := openflow15.FindFieldHeaderByName(fieldName, false)
			field.Value = &openflow15.ByteArrayField{Data: reg.Data, Length: uint8(len(reg.Data))}
			ofMatch.AddField(*field)
		}
	}

	// Handle ct_mark match
	if f.Match.CtMark != 0 || f.Match.CtMarkMask != nil {
		ctMarkField := openflow15.NewCTMarkMatchField(f.Match.CtMark, f.Match.CtMarkMask)
		ofMatch.AddField(*ctMarkField)
	}

	if f.Match.CtLabelHiMask != 0 || f.Match.CtLabelLoMask != 0 || f.Match.CtLabelHi != 0 || f.Match.CtLabelLo != 0 {
		var buf [16]byte
		binary.BigEndian.PutUint64(buf[:8], f.Match.CtLabelHi)
		binary.BigEndian.PutUint64(buf[8:], f.Match.CtLabelLo)
		if f.Match.CtLabelLoMask != 0 || f.Match.CtLabelHiMask != 0 {
			var maskBuf [16]byte
			binary.BigEndian.PutUint64(maskBuf[:8], f.Match.CtLabelHiMask)
			binary.BigEndian.PutUint64(maskBuf[8:], f.Match.CtLabelLoMask)
			ofMatch.AddField(*openflow15.NewCTLabelMatchField(buf, &maskBuf))
		} else {
			ofMatch.AddField(*openflow15.NewCTLabelMatchField(buf, nil))
		}
	}

	// Handle actset_output match
	if f.Match.ActsetOutput != 0 {
		actsetOutputField := openflow15.NewActsetOutputField(f.Match.ActsetOutput)
		ofMatch.AddField(*actsetOutputField)
	}

	// Handle tun_metadata match
	if len(f.Match.TunMetadatas) > 0 {
		for _, m := range f.Match.TunMetadatas {
			data := getDataBytes(m.Data, m.Range)
			var mask []byte
			if m.Range != nil {
				start := int(m.Range.GetOfs())
				length := int(m.Range.GetNbits())
				mask = getMaskBytes(start, length)
			}
			tmField := openflow15.NewTunMetadataField(m.ID, data, mask)
			ofMatch.AddField(*tmField)
		}
	}

	if f.Match.CtIpSa != nil {
		ctIPSaField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_NW_SRC", false)
		ctIPSaField.Value = &openflow15.Ipv4SrcField{
			Ipv4Src: *f.Match.CtIpSa,
		}
		if f.Match.CtIpSaMask != nil {
			mask := new(openflow15.Ipv4SrcField)
			mask.Ipv4Src = *f.Match.CtIpSaMask
			ctIPSaField.HasMask = true
			ctIPSaField.Mask = mask
			ctIPSaField.Length += uint8(mask.Len())
		}
		ofMatch.AddField(*ctIPSaField)
	}

	if f.Match.CtIpDa != nil {
		ctIPDaField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_NW_DST", false)
		ctIPDaField.Value = &openflow15.Ipv4DstField{
			Ipv4Dst: *f.Match.CtIpDa,
		}
		if f.Match.CtIpDaMask != nil {
			mask := new(openflow15.Ipv4DstField)
			mask.Ipv4Dst = *f.Match.CtIpDaMask
			ctIPDaField.HasMask = true
			ctIPDaField.Mask = mask
			ctIPDaField.Length += uint8(mask.Len())
		}
		ofMatch.AddField(*ctIPDaField)
	}

	if f.Match.CtIpProto > 0 {
		ctIPProtoField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_NW_PROTO", false)
		ctIPProtoField.Value = &ProtocolField{Protocol: f.Match.CtIpProto}
		ofMatch.AddField(*ctIPProtoField)
	}

	if f.Match.CtIpv6Sa != nil {
		ctIPv6SaField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_IPV6_SRC", false)
		ctIPv6SaField.Value = &openflow15.Ipv6SrcField{Ipv6Src: *f.Match.CtIpv6Sa}
		if f.Match.CtIpv6SaMask != nil {
			mask := new(openflow15.Ipv6SrcField)
			mask.Ipv6Src = *f.Match.CtIpv6SaMask
			ctIPv6SaField.HasMask = true
			ctIPv6SaField.Mask = mask
			ctIPv6SaField.Length += uint8(mask.Len())
		}
		ofMatch.AddField(*ctIPv6SaField)
	}

	if f.Match.CtIpv6Da != nil {
		ctIPv6DaField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_IPV6_DST", false)
		ctIPv6DaField.Value = &openflow15.Ipv6DstField{Ipv6Dst: *f.Match.CtIpv6Da}
		if f.Match.CtIpv6DaMask != nil {
			mask := new(openflow15.Ipv6DstField)
			mask.Ipv6Dst = *f.Match.CtIpv6DaMask
			ctIPv6DaField.HasMask = true
			ctIPv6DaField.Mask = mask
			ctIPv6DaField.Length += uint8(mask.Len())
		}
		ofMatch.AddField(*ctIPv6DaField)
	}

	if f.Match.CtTpSrcPort > 0 {
		ctTpSrcPortField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_TP_SRC", false)
		ctTpSrcPortField.Value = &PortField{Port: f.Match.CtTpSrcPort}
		ofMatch.AddField(*ctTpSrcPortField)
	}

	if f.Match.CtTpDstPort > 0 {
		ctTpDstPortField, _ := openflow15.FindFieldHeaderByName("NXM_NX_CT_TP_DST", false)
		ctTpDstPortField.Value = &PortField{Port: f.Match.CtTpDstPort}
		ofMatch.AddField(*ctTpDstPortField)
	}

	if f.Match.Icmp6Code != nil {
		icmp6CodeField, _ := openflow15.FindFieldHeaderByName("NXM_NX_ICMPV6_CODE", false)
		icmp6CodeField.Value = &openflow15.IcmpCodeField{Code: *f.Match.Icmp6Code}
		ofMatch.AddField(*icmp6CodeField)
	}

	if f.Match.Icmp6Type != nil {
		icmp6TypeField, _ := openflow15.FindFieldHeaderByName("NXM_NX_ICMPV6_Type", false)
		icmp6TypeField.Value = &openflow15.IcmpTypeField{Type: *f.Match.Icmp6Type}
		ofMatch.AddField(*icmp6TypeField)
	}

	if f.Match.NdTarget != nil {
		ndTargetField, _ := openflow15.FindFieldHeaderByName("NXM_NX_ND_TARGET", f.Match.NdTargetMask != nil)
		ndTargetField.Value = &openflow15.Ipv6DstField{Ipv6Dst: *f.Match.NdTarget}
		if f.Match.NdTargetMask != nil {
			ndTargetField.Mask = &openflow15.Ipv6DstField{Ipv6Dst: *f.Match.NdTargetMask}
		}
		ofMatch.AddField(*ndTargetField)
	}

	if f.Match.NdSll != nil {
		ndSllField, _ := openflow15.FindFieldHeaderByName("NXM_NX_ND_SLL", false)
		ndSllField.Value = &openflow15.EthSrcField{EthSrc: *f.Match.NdSll}
		ofMatch.AddField(*ndSllField)
	}

	if f.Match.NdTll != nil {
		ndTllField, _ := openflow15.FindFieldHeaderByName("NXM_NX_ND_TLL", false)
		ndTllField.Value = &openflow15.EthDstField{EthDst: *f.Match.NdTll}
		ofMatch.AddField(*ndTllField)
	}

	if f.Match.IpTtl != nil {
		ipTtlField, _ := openflow15.FindFieldHeaderByName("NXM_NX_IP_TTL", false)
		ipTtlField.Value = &openflow15.TtlField{Ttl: *f.Match.IpTtl}
		ofMatch.AddField(*ipTtlField)
	}

	// Handle pkt_mark match
	if f.Match.PktMark != 0 {
		pktMarkField, _ := openflow15.FindFieldHeaderByName("NXM_NX_PKT_MARK", f.Match.PktMarkMask != nil)
		pktMarkField.Value = &openflow15.Uint32Message{Data: f.Match.PktMark}
		if f.Match.PktMarkMask != nil {
			pktMarkField.Mask = &openflow15.Uint32Message{Data: *f.Match.PktMarkMask}
		}
		ofMatch.AddField(*pktMarkField)
	}

	if f.Match.Icmp4Code != nil {
		icmp4CodeField, _ := openflow15.FindFieldHeaderByName("NXM_OF_ICMP_CODE", false)
		icmp4CodeField.Value = &openflow15.IcmpCodeField{Code: *f.Match.Icmp4Code}
		ofMatch.AddField(*icmp4CodeField)
	}

	if f.Match.Icmp4Type != nil {
		icmp4TypeField, _ := openflow15.FindFieldHeaderByName("NXM_OF_ICMP_TYPE", false)
		icmp4TypeField.Value = &openflow15.IcmpTypeField{Type: *f.Match.Icmp4Type}
		ofMatch.AddField(*icmp4TypeField)
	}

	return *ofMatch
}

func getRangeEnd(rng *openflow15.NXRange) uint16 {
	return rng.GetOfs() + rng.GetNbits() - 1
}

func getStartFromMask(mask uint32) uint16 {
	var count uint16

	if mask == 0 {
		return 0
	}

	for mask&1 == 0 {
		mask >>= 1
		count++
	}
	return count
}

func merge(regs []*NXRegister) *NXRegister {
	var data, mask uint32
	for _, reg := range regs {
		if reg.Mask != 0 {
			data |= reg.Data << getStartFromMask(reg.Mask)
			mask |= reg.Mask
		} else if reg.Range != nil {
			// no mask, need to compute mask according to range
			end := getRangeEnd(reg.Range)
			start := reg.Range.GetOfs()
			data |= reg.Data << start
			mask |= ((uint32(1) << (end - start + 1)) - 1) << start
		} else {
			// full range
			data |= reg.Data
			mask |= 0xffffffff
		}
	}
	return &NXRegister{
		ID:   regs[0].ID,
		Data: data,
		Mask: mask,
	}
}

func getDataBytes(value interface{}, nxRange *openflow15.NXRange) []byte {
	start := int(nxRange.GetOfs())
	length := int(nxRange.GetNbits())
	switch v := value.(type) {
	case uint32:
		rst := getUint32WithOfs(v, start, length)
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, rst)
		return data
	case uint64:
		rst := getUint64WithOfs(v, start, length)
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, rst)
		return data
	case []byte:
		return v
	}
	return nil
}

func getUint32WithOfs(data uint32, start, length int) uint32 {
	return data << (32 - length) >> (32 - length - start)
}

func getUint64WithOfs(data uint64, start, length int) uint64 {
	return data << (64 - length) >> (64 - length - start)
}

func getMaskBytes(start, length int) []byte {
	end := start + length - 1
	if end < 32 {
		data := make([]byte, 4)
		mask := getUint32WithOfs(^uint32(0), start, length)
		binary.BigEndian.PutUint32(data, mask)
		return data
	}
	if end < 64 {
		data := make([]byte, 8)
		mask := getUint64WithOfs(^uint64(0), start, length)
		binary.BigEndian.PutUint64(data, mask)
		return data
	}
	i := 0
	bytesLength := 8 * ((end + 63) / 64)
	data := make([]byte, bytesLength)
	for i < bytesLength {
		subStart := i * 64
		subEnd := i*64 + 63
		if start > subEnd {
			binary.BigEndian.PutUint64(data[i:], uint64(0))
			i += 8
			continue
		}
		var rngStart, rngLength int
		if start < subStart {
			rngStart = 0
		} else {
			rngStart = start - subStart
		}
		if end > subEnd {
			rngLength = 64 - rngStart
		} else {
			rngLength = (end - subStart) - rngStart + 1
		}
		data = append(data, getMaskBytes(rngStart, rngLength)...)
		i += 8
	}
	return data
}

// Install all flow Actions
func (f *Flow) installFlowActions(flowMod *openflow15.FlowMod,
	instr openflow15.Instruction) error {
	var actInstr openflow15.Instruction
	addActn := false
	var err error

	// Create a apply_action instruction to be used if its not already created
	switch instr.(type) {
	case *openflow15.InstrActions:
		actInstr = instr
	default:
		actInstr = openflow15.NewInstrApplyActions()
	}

	// Loop thru all Actions in reversed order, and prepend the action into instruction, so that the Actions is in the
	// order as it is added by the client.
	for i := len(f.flowActions) - 1; i >= 0; i-- {
		flowAction := f.flowActions[i]
		switch flowAction.ActionType {
		case ActTypeSetVlan:
			// Push Vlan Tag action
			pushVlanAction := openflow15.NewActionPushVlan(0x8100)

			// Set Outer vlan tag field
			vlanField := openflow15.NewVlanIdField(flowAction.vlanId, nil)
			setVlanAction := openflow15.NewActionSetField(*vlanField)

			// Prepend push vlan & setvlan Actions to existing instruction
			err = actInstr.AddAction(setVlanAction, true)
			if err != nil {
				return err
			}
			err = actInstr.AddAction(pushVlanAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added pushvlan action: %+v, setVlan Actions: %+v",
				pushVlanAction, setVlanAction)

		case ActTypePopVlan:
			// Create pop vln action
			popVlan := openflow15.NewActionPopVlan()

			// Add it to instruction
			err = actInstr.AddAction(popVlan, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added popVlan action: %+v", popVlan)

		case ActTypePushMpls:
			// Create push mpls action
			pushMpls := (&PushMPLSAction{EtherType: flowAction.mplsEtherType}).GetActionMessage()

			// Add it to instruction
			err = actInstr.AddAction(pushMpls, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added pushMpls action: %+v", pushMpls)

		case ActTypePopMpls:
			// Create pop mpls action
			popMpls := (&PopMPLSAction{EtherType: flowAction.mplsEtherType}).GetActionMessage()

			// Add it to instruction
			err = actInstr.AddAction(popMpls, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added popMpls action: %+v", popMpls)

		case ActTypeSetDstMac:
			// Set Outer MacDA field
			macDaField := openflow15.NewEthDstField(flowAction.macAddr, nil)
			setMacDaAction := openflow15.NewActionSetField(*macDaField)

			// Add set macDa action to the instruction
			err = actInstr.AddAction(setMacDaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setMacDa action: %+v", setMacDaAction)

		case ActTypeSetSrcMac:
			// Set Outer MacSA field
			macSaField := openflow15.NewEthSrcField(flowAction.macAddr, nil)
			setMacSaAction := openflow15.NewActionSetField(*macSaField)

			// Add set macDa action to the instruction
			err = actInstr.AddAction(setMacSaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setMacSa Action: %+v", setMacSaAction)

		case ActTypeSetTunnelID:
			// Set tunnelId field
			tunnelIdField := openflow15.NewTunnelIdField(flowAction.tunnelId)
			setTunnelAction := openflow15.NewActionSetField(*tunnelIdField)

			// Add set tunnel action to the instruction
			err = actInstr.AddAction(setTunnelAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setTunnelId Action: %+v", setTunnelAction)

		case "setMetadata":
			// Set Metadata instruction
			metadataInstr := openflow15.NewInstrWriteMetadata(flowAction.metadata, flowAction.metadataMask)

			// Add the instruction to flowmod
			flowMod.AddInstruction(metadataInstr)

		case ActTypeSetSrcIP:
			// Set IP src
			ipSaField := openflow15.NewIpv4SrcField(flowAction.ipAddr, nil)
			setIPSaAction := openflow15.NewActionSetField(*ipSaField)

			// Add set action to the instruction
			err = actInstr.AddAction(setIPSaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setIPSa Action: %+v", setIPSaAction)

		case ActTypeSetDstIP:
			// Set IP dst
			ipDaField := openflow15.NewIpv4DstField(flowAction.ipAddr, nil)
			setIPDaAction := openflow15.NewActionSetField(*ipDaField)

			// Add set action to the instruction
			err = actInstr.AddAction(setIPDaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setIPDa Action: %+v", setIPDaAction)

		case ActTypeSetTunnelSrcIP:
			// Set tunnel src addr field
			tunnelSrcField := openflow15.NewTunnelIpv4SrcField(flowAction.ipAddr, nil)
			setTunnelSrcAction := openflow15.NewActionSetField(*tunnelSrcField)

			// Add set tunnel action to the instruction
			err = actInstr.AddAction(setTunnelSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setTunSa Action: %+v", setTunnelSrcAction)

		case ActTypeSetTunnelDstIP:
			// Set tunnel dst addr field
			tunnelDstField := openflow15.NewTunnelIpv4DstField(flowAction.ipAddr, nil)
			setTunnelAction := openflow15.NewActionSetField(*tunnelDstField)

			// Add set tunnel action to the instruction
			err = actInstr.AddAction(setTunnelAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setTunDa Action: %+v", setTunnelAction)

		case ActTypeSetDSCP:
			// Set DSCP field
			ipDscpField := openflow15.NewIpDscpField(flowAction.dscp, nil)
			setIPDscpAction := openflow15.NewActionSetField(*ipDscpField)

			// Add set action to the instruction
			err = actInstr.AddAction(setIPDscpAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setDscp Action: %+v", setIPDscpAction)

		case ActTypeSetARPOper:
			// Set ARP operation type field
			arpOpField := openflow15.NewArpOperField(flowAction.arpOper)
			setARPOpAction := openflow15.NewActionSetField(*arpOpField)

			// Add set ARP operation type action to the instruction
			err = actInstr.AddAction(setARPOpAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setArpOper Action: %+v", setARPOpAction)

		case ActTypeSetARPSHA:
			// Set ARP_SHA field
			arpShaField := openflow15.NewArpShaField(flowAction.macAddr)
			setARPShaAction := openflow15.NewActionSetField(*arpShaField)

			// Append set ARP_SHA action to the instruction
			err = actInstr.AddAction(setARPShaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPSha Action: %+v", setARPShaAction)

		case ActTypeSetARPTHA:
			// Set ARP_THA field
			arpThaField := openflow15.NewArpThaField(flowAction.macAddr)
			setARPThaAction := openflow15.NewActionSetField(*arpThaField)

			// Add set ARP_THA action to the instruction
			err = actInstr.AddAction(setARPThaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPTha Action: %+v", setARPThaAction)

		case ActTypeSetARPSPA:
			// Set ARP_SPA field
			arpSpaField := openflow15.NewArpSpaField(flowAction.ipAddr)
			setARPSpaAction := openflow15.NewActionSetField(*arpSpaField)

			// Add set ARP_SPA action to the instruction
			err = actInstr.AddAction(setARPSpaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPSpa Action: %+v", setARPSpaAction)
		case ActTypeSetARPTPA:
			// Set ARP_TPA field
			arpTpaField := openflow15.NewArpTpaField(flowAction.ipAddr)
			setARPTpaAction := openflow15.NewActionSetField(*arpTpaField)

			// Add set ARP_SPA action to the instruction
			err = actInstr.AddAction(setARPTpaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPTpa Action: %+v", setARPTpaAction)
		case ActTypeSetTCPsPort:
			// Set TCP src
			tcpSrcField := openflow15.NewTcpSrcField(flowAction.l4Port)
			setTCPSrcAction := openflow15.NewActionSetField(*tcpSrcField)

			// Add set action to the instruction
			err = actInstr.AddAction(setTCPSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setTCPSrc Action: %+v", setTCPSrcAction)

		case ActTypeSetTCPdPort:
			// Set TCP dst
			tcpDstField := openflow15.NewTcpDstField(flowAction.l4Port)
			setTCPDstAction := openflow15.NewActionSetField(*tcpDstField)

			// Add set action to the instruction
			err = actInstr.AddAction(setTCPDstAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setTCPDst Action: %+v", setTCPDstAction)

		case ActTypeSetUDPsPort:
			// Set UDP src
			udpSrcField := openflow15.NewUdpSrcField(flowAction.l4Port)
			setUDPSrcAction := openflow15.NewActionSetField(*udpSrcField)

			// Add set action to the instruction
			err = actInstr.AddAction(setUDPSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setUDPSrc Action: %+v", setUDPSrcAction)

		case ActTypeSetUDPdPort:
			// Set UDP dst
			udpDstField := openflow15.NewUdpDstField(flowAction.l4Port)
			setUDPDstAction := openflow15.NewActionSetField(*udpDstField)

			// Add set action to the instruction
			err = actInstr.AddAction(setUDPDstAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setUDPDst Action: %+v", setUDPDstAction)
		case ActTypeSetSCTPsPort:
			// Set SCTP src
			sctpSrcField := openflow15.NewSctpSrcField(flowAction.l4Port)
			setSCTPSrcAction := openflow15.NewActionSetField(*sctpSrcField)

			// Add set action to the instruction
			err = actInstr.AddAction(setSCTPSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setSCTPSrc Action: %+v", setSCTPSrcAction)

		case ActTypeSetSCTPdPort:
			// Set SCTP dst
			sctpDstField := openflow15.NewSctpSrcField(flowAction.l4Port)
			setSCTPDstAction := openflow15.NewActionSetField(*sctpDstField)

			// Add set action to the instruction
			err = actInstr.AddAction(setSCTPDstAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setSCTPSrc Action: %+v", setSCTPDstAction)

		case ActTypeNXLoad:
			// Create NX load action
			loadAct := flowAction.loadAct
			loadRegAction := loadAct.GetActionMessage()

			// Add load action to the instruction
			err = actInstr.AddAction(loadRegAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added loadReg Action: %+v", loadRegAction)

		case ActTypeSetField:
			setFieldAct := flowAction.setFieldAct
			setFieldAction := setFieldAct.GetActionMessage()

			// Add set action to the instruction
			err = actInstr.AddAction(setFieldAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setField Action: %+v", setFieldAction)

		case ActTypeCopyField:
			copyFieldAct := flowAction.copyFieldAct
			copyFieldActMsg := copyFieldAct.GetActionMessage()

			// Add load action to the instruction
			err = actInstr.AddAction(copyFieldActMsg, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added copyField Action: %+v", copyFieldActMsg)

		case ActTypeNXMove:
			// Create NX move action
			moveRegAction := flowAction.moveAct.GetActionMessage()

			// Add move action to the instruction
			err = actInstr.AddAction(moveRegAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added moveReg Action: %+v", moveRegAction)

		case ActTypeNXCT:
			ctAction := flowAction.connTrack.GetActionMessage()

			// Add conn_track action to the instruction
			err = actInstr.AddAction(ctAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added ct Action: %+v", ctAction)

		case ActTypeNXConjunction:
			// Create NX conjunction action
			conjAction := flowAction.conjunction.GetActionMessage()

			// Add conn_track action to the instruction
			err = actInstr.AddAction(conjAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added conjunction Action: %+v", conjAction)

		case ActTypeDecTTL:
			decTtlAction := openflow15.NewActionDecNwTtl()
			// Add dec_ttl action to the instruction
			err = actInstr.AddAction(decTtlAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added decTTL Action: %+v", decTtlAction)
		case ActTypeNXResubmit:
			resubmitAction := flowAction.resubmit
			// Add resubmit action to the instruction
			err = actInstr.AddAction(resubmitAction.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added resubmit Action: %+v", resubmitAction)
		case ActTypeNXLearn:
			learnAction := flowAction.learn
			// Add learn action to the instruction
			err = actInstr.AddAction(learnAction.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added learn Action: %+v", learnAction)
		case ActTypeNXNote:
			notes := flowAction.notes
			noteAction := openflow15.NewNXActionNote()
			noteAction.Note = notes
			// Add note action to the instruction
			err = actInstr.AddAction(noteAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added note Action: %+v", noteAction)
		case ActTypeNXOutput:
			nxOutput := flowAction.nxOutput
			// Add NXOutput action to the instruction
			err = actInstr.AddAction(nxOutput.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added nxOutput Action: %+v", nxOutput)
		case ActTypeController:
			act := flowAction.controller
			err = actInstr.AddAction(act.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true
			log.Debugf("flow action: Added controller Action: %+v", act)
		default:
			log.Fatalf("Unknown action type %s", flowAction.ActionType)
			return UnknownActionTypeError
		}
	}

	// Add the instruction to flow if its not already added
	if (addActn) && (actInstr != instr) {
		// Add the instruction to flowmod
		flowMod.AddInstruction(actInstr)
	}

	return nil
}

// GenerateFlowModMessage translates the Flow a FlowMod message according to the commandType.
func (f *Flow) GenerateFlowModMessage(commandType int) (flowMod *openflow15.FlowMod, err error) {
	// Create a flowmode entry
	flowMod = openflow15.NewFlowMod()
	flowMod.TableId = f.Table.TableId
	flowMod.Priority = f.Match.Priority
	// Cookie ID could be set by client, using globalFlowID if not set
	if f.CookieID == 0 {
		f.CookieID = globalFlowID // FIXME: need a better id allocation
		globalFlowID += 1
	}
	flowMod.Cookie = f.CookieID
	if f.CookieMask != nil {
		flowMod.CookieMask = *f.CookieMask
	}
	if f.HardTimeout > 0 {
		flowMod.HardTimeout = f.HardTimeout
	}
	if f.IdleTimeout > 0 {
		flowMod.IdleTimeout = f.IdleTimeout
	}
	flowMod.Command = uint8(commandType)

	// convert match fields to openflow 1.5 format
	flowMod.Match = f.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)
	if commandType != openflow15.FC_DELETE && commandType != openflow15.FC_DELETE_STRICT {

		// Based on the next elem, decide what to install
		switch f.NextElem.Type() {
		case "table":
			// Get the instruction set from the element
			instr := f.NextElem.GetFlowInstr()

			// Check if there are any flow actions to perform
			err = f.installFlowActions(flowMod, instr)
			if err != nil {
				return
			}

			// Add the instruction to flowmod
			flowMod.AddInstruction(instr)

			log.Debugf("flow install: added goto table instr: %+v", instr)

		case "flood":
			fallthrough
		case "output":
			// Get the instruction set from the element
			instr := f.NextElem.GetFlowInstr()

			// Add the instruction to flowmod if its not nil
			// a nil instruction means drop action
			if instr != nil {

				// Check if there are any flow actions to perform
				err = f.installFlowActions(flowMod, instr)
				if err != nil {
					return
				}

				flowMod.AddInstruction(instr)

				log.Debugf("flow install: added next instr: %+v", instr)
			}
		case "group":
			fallthrough
		case "Resubmit":
			// Get the instruction set from the element
			instr := f.NextElem.GetFlowInstr()

			// Add the instruction to flowmod if its not nil
			// a nil instruction means drop action
			if instr != nil {

				// Check if there are any flow actions to perform
				err = f.installFlowActions(flowMod, instr)
				if err != nil {
					return
				}

				flowMod.AddInstruction(instr)

				log.Debugf("flow install: added next instr: %+v", instr)
			}
		case "empty":
			// Get the instruction set from the element. This instruction is InstrActions with no actions
			instr := f.NextElem.GetFlowInstr()
			if instr != nil {

				// Check if there are any flow actions to perform
				err = f.installFlowActions(flowMod, instr)
				if err != nil {
					return
				}
				if len(instr.(*openflow15.InstrActions).Actions) > 0 {
					flowMod.AddInstruction(instr)
				}

				log.Debugf("flow install: added next instr: %+v", instr)
			}

		default:
			log.Fatalf("Unknown Fgraph element type %s", f.NextElem.Type())
			err = UnknownElementTypeError
			return
		}
	}
	return
}

// Install a flow entry
func (f *Flow) install() error {
	command := openflow15.FC_MODIFY_STRICT
	// Add or modify
	if !f.isInstalled {
		command = openflow15.FC_ADD
	}
	flowMod, err := f.GenerateFlowModMessage(command)
	if err != nil {
		return err
	}
	log.Debugf("Sending flowmod: %+v", flowMod)

	// Send the message
	if err := f.Table.Switch.Send(flowMod); err != nil {
		return err
	}

	// Mark it as installed
	f.isInstalled = true

	return nil
}

// updateInstallStatus changes isInstalled value.
func (f *Flow) UpdateInstallStatus(installed bool) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.isInstalled = installed
}

// Set Next element in the Fgraph. This determines what actions will be
// part of the flow's instruction set
func (f *Flow) Next(elem FgraphElem) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	// Set the next element in the graph
	f.NextElem = elem

	// Install the flow entry
	return f.install()
}

// Special action on the flow to set vlan id
func (f *Flow) SetVlan(vlanId uint16) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetVlan
	action.vlanId = vlanId

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set vlan id
func (f *Flow) PopVlan() error {
	action := new(FlowAction)
	action.ActionType = ActTypePopVlan

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to pop mpls ethertype
func (f *Flow) PopMpls(etherType uint16) error {
	action := new(FlowAction)
	action.ActionType = ActTypePopMpls
	action.mplsEtherType = etherType

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to push mpls ethertype
func (f *Flow) PushMpls(etherType uint16) error {
	action := new(FlowAction)
	action.ActionType = ActTypePushMpls
	action.mplsEtherType = etherType

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set mac dest addr
func (f *Flow) SetMacDa(macDa net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetDstMac
	action.macAddr = macDa

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set mac source addr
func (f *Flow) SetMacSa(macSa net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetSrcMac
	action.macAddr = macSa

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set an ip field
func (f *Flow) SetIPField(ip net.IP, field string) error {
	action := new(FlowAction)
	action.ipAddr = ip
	switch field {
	case "Src":
		action.ActionType = ActTypeSetSrcIP
	case "Dst":
		action.ActionType = ActTypeSetDstIP
	case "TunSrc":
		action.ActionType = ActTypeSetTunnelSrcIP
	case "TunDst":
		action.ActionType = ActTypeSetTunnelDstIP
	default:
		return errors.New("field not supported")
	}

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set arp_spa field
func (f *Flow) SetARPSpa(ip net.IP) error {
	action := new(FlowAction)
	action.ipAddr = ip
	action.ActionType = ActTypeSetARPSPA

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set arp_spa field
func (f *Flow) SetARPTpa(ip net.IP) error {
	action := new(FlowAction)
	action.ipAddr = ip
	action.ActionType = ActTypeSetARPTPA

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set a L4 field
func (f *Flow) SetL4Field(port uint16, field string) error {
	action := new(FlowAction)
	action.l4Port = port

	switch field {
	case "TCPSrc":
		action.ActionType = ActTypeSetTCPsPort
	case "TCPDst":
		action.ActionType = ActTypeSetTCPdPort
	case "UDPSrc":
		action.ActionType = ActTypeSetUDPsPort
	case "UDPDst":
		action.ActionType = ActTypeSetUDPdPort
	case "SCTPSrc":
		action.ActionType = ActTypeSetSCTPsPort
	case "SCTPDst":
		action.ActionType = ActTypeSetSCTPdPort
	default:
		return errors.New("field not supported")
	}

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special actions on the flow to set metadata
func (f *Flow) SetMetadata(metadata, metadataMask uint64) error {
	action := new(FlowAction)
	action.ActionType = "setMetadata"
	action.metadata = metadata
	action.metadataMask = metadataMask

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special actions on the flow to set vlan id
func (f *Flow) SetTunnelId(tunnelId uint64) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetTunnelID
	action.tunnelId = tunnelId

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special actions on the flow to set dscp field
func (f *Flow) SetDscp(dscp uint8) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetDSCP
	action.dscp = dscp

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// unset dscp field
func (f *Flow) UnsetDscp() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	// Delete to the action from db
	for idx, act := range f.flowActions {
		if act.ActionType == ActTypeSetDSCP {
			f.flowActions = append(f.flowActions[:idx], f.flowActions[idx+1:]...)
		}
	}

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) SetARPOper(arpOp uint16) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetARPOper
	action.arpOper = arpOp

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set ARP source host addr
func (f *Flow) SetARPSha(arpSha net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetARPSHA
	action.macAddr = arpSha

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special action on the flow to set ARP target host addr
func (f *Flow) SetARPTha(arpTha net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetARPTHA
	action.macAddr = arpTha

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special Actions on the flow to load data into OXM/NXM field
func (f *Flow) LoadReg(fieldName string, data uint64, dataRange *openflow15.NXRange) error {
	loadAct, err := NewNXLoadAction(fieldName, data, dataRange)
	if err != nil {
		return err
	}
	if f.Table != nil && f.Table.Switch != nil {
		loadAct.ResetFieldLength(f.Table.Switch)
	}
	action := new(FlowAction)
	action.ActionType = loadAct.GetActionType()
	action.loadAct = loadAct
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) SetField(field *openflow15.MatchField) error {
	setField := NewSetFieldAction(field)
	action := new(FlowAction)
	action.ActionType = setField.GetActionType()
	action.setFieldAct = setField

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}
	return nil
}

func (f *Flow) CopyField(nBits uint16, srcOffset uint16, dstOffset uint16,
	srcOxmId *openflow15.OxmId, dstOxmId *openflow15.OxmId) error {
	copyFieldAct := NewCopyFieldAction(nBits, srcOffset, dstOffset, srcOxmId, dstOxmId)
	action := new(FlowAction)
	action.ActionType = copyFieldAct.GetActionType()
	action.copyFieldAct = copyFieldAct

	// Add to the action db
	f.flowActions = append(f.flowActions, action)

	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}
	return nil
}

// Special Actions on the flow to move data from src_field[rng] to dst_field[rng]
func (f *Flow) MoveRegs(srcName string, dstName string, srcRange *openflow15.NXRange, dstRange *openflow15.NXRange) error {
	moveAct, err := NewNXMoveAction(srcName, dstName, srcRange, dstRange)
	if err != nil {
		return err
	}
	if f.Table != nil && f.Table.Switch != nil {
		moveAct.ResetFieldsLength(f.Table.Switch)
	}

	action := new(FlowAction)
	action.ActionType = moveAct.GetActionType()
	action.moveAct = moveAct
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) Resubmit(ofPort uint16, tableID uint8) error {
	action := new(FlowAction)
	action.resubmit = NewResubmit(&ofPort, &tableID)
	action.ActionType = action.resubmit.GetActionType()
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special actions on the flow for connection trackng
func (f *Flow) ConnTrack(commit bool, force bool, tableID *uint8, zoneID *uint16, execActions ...openflow15.Action) error {
	connTrack := &NXConnTrackAction{
		commit:  commit,
		force:   force,
		table:   tableID,
		zoneImm: zoneID,
		actions: execActions,
	}
	action := new(FlowAction)
	action.ActionType = connTrack.GetActionType()
	action.connTrack = connTrack
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special Actions to to the flow to set conjunctions
// Note:
//  1. nclause should be in [2, 64].
//  2. clause value should be less than or equals to ncluase, and its value should be started from 1.
//     actual clause in libopenflow messages is started from 0, here would decrement 1 to keep the display
//     value is consistent with expected configuration
func (f *Flow) AddConjunction(conjID uint32, clause uint8, nClause uint8) error {
	conjunction, err := NewNXConjunctionAction(conjID, clause, nClause)
	if err != nil {
		return nil
	}

	action := new(FlowAction)
	action.ActionType = conjunction.GetActionType()
	action.conjunction = conjunction
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) DelConjunction(conjID uint32) error {
	found := false

	f.lock.Lock()
	defer f.lock.Unlock()

	// Remove conjunction from the action db
	for i, act := range f.flowActions {
		if act.ActionType == ActTypeNXConjunction {
			conjuncAct := act.conjunction
			if conjID == conjuncAct.ID {
				f.flowActions = append(f.flowActions[:i], f.flowActions[i+1:]...)
				found = true
			}
		}
	}

	if !found {
		return nil
	}

	// Return EmptyFlowActionError if there is no Actions left in flow
	if len(f.flowActions) == 0 {
		return EmptyFlowActionError
	}
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special Actions to the flow to dec TTL
func (f *Flow) DecTTL() error {
	action := new(FlowAction)
	action.ActionType = ActTypeDecTTL
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Special Actions to the flow to learn from the current packet and generate a new flow entry.
func (f *Flow) Learn(learn *FlowLearn) error {
	action := new(FlowAction)
	action.ActionType = ActTypeNXLearn
	action.learn = learn
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) Note(data []byte) error {
	action := new(FlowAction)
	action.ActionType = ActTypeNXNote
	action.notes = data
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}
func (f *Flow) OutputReg(name string, start int, end int) error {
	action := new(FlowAction)
	var err error
	action.nxOutput, err = NewNXOutput(name, start, end)
	if err != nil {
		return err
	}
	action.ActionType = action.nxOutput.GetActionType()

	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

func (f *Flow) Controller(reason uint8) error {
	action := new(FlowAction)
	action.controller = &NXController{
		ControllerID: f.Table.Switch.ctrlID,
		Reason:       reason,
	}
	action.ActionType = action.controller.GetActionType()
	f.lock.Lock()
	defer f.lock.Unlock()

	// Add to the action db
	f.flowActions = append(f.flowActions, action)
	// If the flow entry was already installed, re-install it
	if f.isInstalled {
		return f.install()
	}

	return nil
}

// Delete the flow
func (f *Flow) Delete() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	// Delete from ofswitch
	if f.isInstalled {
		// Create a flowmode entry
		flowMod := openflow15.NewFlowMod()
		flowMod.Command = openflow15.FC_DELETE_STRICT
		flowMod.TableId = f.Table.TableId
		flowMod.Priority = f.Match.Priority
		flowMod.Cookie = f.CookieID
		if f.CookieMask != nil {
			flowMod.CookieMask = *f.CookieMask
		} else {
			flowMod.CookieMask = ^uint64(0)
		}
		flowMod.OutPort = openflow15.P_ANY
		flowMod.OutGroup = openflow15.OFPG_ANY
		flowMod.Match = f.xlateMatch()

		log.Debugf("Sending DELETE flowmod: %+v", flowMod)

		// Send the message
		if err := f.Table.Switch.Send(flowMod); err != nil {
			return err
		}
	}

	// Delete it from the Table
	flowKey := f.flowKey()
	return f.Table.DeleteFlow(flowKey)
}

func (f *Flow) SetRealized() {
	f.statusLock.Lock()
	defer f.statusLock.Unlock()
	f.realized = true
}

// IsRealized gets flow realized status
func (f *Flow) IsRealized() bool {
	f.statusLock.Lock()
	defer f.statusLock.Unlock()
	return f.realized
}

// MonitorRealizeStatus sends MultipartRequest to get current flow status, it is calling if needs to check
// flow's realized status
func (f *Flow) MonitorRealizeStatus() {
	stats, err := f.Table.Switch.DumpFlowStats(f.CookieID, f.CookieMask, &f.Match, &f.Table.TableId)
	if err != nil {
		f.realized = false
	}
	if stats != nil {
		f.realized = true
	}
}

func (f *Flow) GetBundleMessage(command int) (*FlowBundleMessage, error) {
	var flowMod *openflow15.FlowMod
	var err error
	if f.NextElem != nil {
		flowMod, err = f.GenerateFlowModMessage(command)
	} else {
		flowMod, err = f.generateFlowMessage(command)
	}
	if err != nil {
		return nil, err
	}
	return &FlowBundleMessage{flowMod}, nil
}

func (f *Flow) ApplyAction(action OFAction) {
	f.appliedActions = append(f.appliedActions, action)
}

func (f *Flow) ApplyActions(actions []OFAction) {
	f.appliedActions = append(f.appliedActions, actions...)
}

func (f *Flow) ResetApplyActions(actions []OFAction) {
	f.appliedActions = nil
	f.ApplyActions(actions)
}

func (f *Flow) WriteAction(action OFAction) {
	f.writtenActions = append(f.writtenActions, action)
}

func (f *Flow) WriteActions(actions []OFAction) {
	f.writtenActions = append(f.writtenActions, actions...)
}

func (f *Flow) ResetWriteActions(actions []OFAction) {
	f.writtenActions = nil
	f.WriteActions(actions)
}

func (f *Flow) WriteMetadata(metadata uint64, metadataMask uint64) {
	f.metadata = &writeMetadata{metadata, metadataMask}
}

func (f *Flow) Goto(tableID uint8) {
	f.gotoTable = &tableID
}

func (f *Flow) ClearActions() {
	f.clearActions = true
}

func (f *Flow) Drop() {
	f.appliedActions = nil
	f.metadata = nil
	f.writtenActions = nil
	f.clearActions = false
	f.gotoTable = nil
	f.meter = nil
}

func (f *Flow) generateFlowMessage(commandType int) (flowMod *openflow15.FlowMod, err error) {
	flowMod = openflow15.NewFlowMod()
	flowMod.TableId = f.Table.TableId
	flowMod.Priority = f.Match.Priority
	// Cookie ID could be set by client, using globalFlowID if not set
	if f.CookieID == 0 {
		f.CookieID = globalFlowID // FIXME: need a better id allocation
		globalFlowID += 1
	}
	flowMod.Cookie = f.CookieID
	if f.CookieMask != nil {
		flowMod.CookieMask = *f.CookieMask
	}
	if f.HardTimeout > 0 {
		flowMod.HardTimeout = f.HardTimeout
	}
	if f.IdleTimeout > 0 {
		flowMod.IdleTimeout = f.IdleTimeout
	}
	flowMod.Command = uint8(commandType)

	// convert match fields to openflow 1.5 format
	flowMod.Match = f.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)
	if commandType != openflow15.FC_DELETE && commandType != openflow15.FC_DELETE_STRICT {
		if f.metadata != nil {
			writeMdInstruction := openflow15.NewInstrWriteMetadata(f.metadata.data, f.metadata.mask)
			flowMod.AddInstruction(writeMdInstruction)
		}
		if len(f.appliedActions) > 0 {
			appliedInstruction := openflow15.NewInstrApplyActions()
			for _, act := range f.appliedActions {
				err := appliedInstruction.AddAction(act.GetActionMessage(), false)
				if err != nil {
					return nil, err
				}
			}
			flowMod.AddInstruction(appliedInstruction)
		}
		if f.clearActions {
			clearInstruction := new(openflow15.InstrActions)
			clearInstruction.InstrHeader = openflow15.InstrHeader{
				Type:   openflow15.InstrType_CLEAR_ACTIONS,
				Length: 8,
			}
			flowMod.AddInstruction(clearInstruction)
		}
		if len(f.writtenActions) > 0 {
			writeInstruction := openflow15.NewInstrWriteActions()
			for _, act := range f.writtenActions {
				if err := writeInstruction.AddAction(act.GetActionMessage(), false); err != nil {
					return nil, err
				}
			}
			flowMod.AddInstruction(writeInstruction)
		}
		if f.gotoTable != nil {
			gotoTableInstruction := openflow15.NewInstrGotoTable(*f.gotoTable)
			flowMod.AddInstruction(gotoTableInstruction)
		}
	}
	return flowMod, nil
}

// Send generates a FlowMod message according the operationType, and then sends it to the OFSwitch.
func (f *Flow) Send(operationType int) error {
	flowMod, err := f.generateFlowMessage(operationType)
	if err != nil {
		return err
	}
	// Send the message
	return f.Table.Switch.Send(flowMod)
}

func (f *Flow) CopyActionsToNewFlow(newFlow *Flow) {
	newFlow.appliedActions = f.appliedActions
	newFlow.clearActions = f.clearActions
	newFlow.writtenActions = f.writtenActions
	newFlow.gotoTable = f.gotoTable
	newFlow.metadata = f.metadata
	newFlow.meter = f.meter
}
