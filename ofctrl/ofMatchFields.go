package ofctrl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
)

type Uint32WithMask struct {
	Value uint32
	Mask  uint32
}

type Uint64WithMask struct {
	Value uint64
	Mask  uint64
}

type DataWithMask struct {
	Value []byte
	Mask  []byte
}

type CTStatesChecker Uint32WithMask

type Matchers struct {
	matches []*MatchField
}

func (m *Matchers) GetMatch(class uint16, field uint8) *MatchField {
	for _, m := range m.matches {
		if m.Class == class && m.Field == field {
			return m
		}
	}
	return nil
}

func (m *Matchers) GetMatchByName(name string) *MatchField {
	mfHeader, err := openflow15.FindFieldHeaderByName(name, false)
	if err != nil {
		return nil
	}
	return m.GetMatch(mfHeader.Class, mfHeader.Field)
}

func (s *CTStatesChecker) IsNew() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_NEW_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnNew() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_NEW_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsRpl() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_RPL_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnRpl() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_RPL_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsRel() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_REL_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnRel() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_REL_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsEst() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_EST_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnEst() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_EST_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsTrk() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_TRK_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnTrk() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_TRK_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsInv() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_INV_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnInv() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_INV_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsSNAT() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_SNAT_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnSNAT() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_SNAT_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

func (s *CTStatesChecker) IsDNAT() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_SNAT_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData != 0)
}

func (s *CTStatesChecker) IsUnDNAT() bool {
	checkData := uint32(1 << openflow15.NX_CT_STATE_DNAT_OFS)
	return (s.Mask&checkData != 0) && (s.Value&checkData == 0)
}

type MatchField struct {
	*openflow15.MatchField
	nickName string
	name     string
}

func (m *MatchField) GetNickName() string {
	return m.nickName
}

func (m *MatchField) GetName() string {
	return m.name
}

func (m *MatchField) GetValue() interface{} {
	switch v := m.Value.(type) {
	case *openflow15.InPortField:
		return v.InPort
	case *openflow15.MetadataField:
		value := v.Metadata
		if !m.HasMask {
			return value
		}
		maskData, _ := m.Mask.(*openflow15.MetadataField)
		return Uint64WithMask{
			Value: value,
			Mask:  maskData.Metadata,
		}
	case *openflow15.EthDstField:
		return v.EthDst
	case *openflow15.EthSrcField:
		return v.EthSrc
	case *openflow15.EthTypeField:
		return v.EthType
	case *openflow15.VlanIdField:
		return v.VlanId
	case *openflow15.IpDscpField:
		value, _ := getUint8(m.Value)
		return value
	case *openflow15.IpProtoField:
		value, _ := getUint8(m.Value)
		return value
	case *openflow15.Ipv4SrcField:
		value := v.Ipv4Src
		if !m.HasMask {
			return value
		}
		maskData, _ := m.Mask.(*openflow15.Ipv4SrcField)
		mask := maskData.Ipv4Src
		return net.IPNet{
			IP:   value,
			Mask: net.IPv4Mask(mask[0], mask[1], mask[2], mask[3]),
		}
	case *openflow15.Ipv4DstField:
		value := v.Ipv4Dst
		if !m.HasMask {
			return value
		}
		maskData, _ := m.Mask.(*openflow15.Ipv4DstField)
		mask := maskData.Ipv4Dst
		return net.IPNet{
			IP:   value,
			Mask: net.IPv4Mask(mask[0], mask[1], mask[2], mask[3]),
		}
	case *openflow15.PortField:
		value, _ := getUint16(m.Value)
		return value
	case *openflow15.ArpOperField:
		return v.ArpOper
	case *openflow15.ArpXHaField:
		return v.ArpHa
	case *openflow15.ArpXPaField:
		return v.ArpPa
	case *openflow15.Ipv6SrcField:
		return v.Ipv6Src
	case *openflow15.Ipv6DstField:
		return v.Ipv6Dst
	case *openflow15.MplsLabelField:
		return v.MplsLabel
	case *openflow15.MplsBosField:
		return v.MplsBos
	case *openflow15.TunnelIdField:
		return v.TunnelId
	case *openflow15.TcpFlagsField:
		return v.TcpFlags
	case *openflow15.TunnelIpv4SrcField:
		return v.TunnelIpv4Src
	case *openflow15.TunnelIpv4DstField:
		return v.TunnelIpv4Dst
	case *openflow15.Uint16Message:
		return v.Data
	case *openflow15.Uint32Message:
		switch m.Field {
		case openflow15.NXM_NX_CT_STATE:
			fieldValue, _ := getCTState(m.MatchField)
			return fieldValue
		case openflow15.NXM_NX_REG0:
			fallthrough
		case openflow15.NXM_NX_REG1:
			fallthrough
		case openflow15.NXM_NX_REG2:
			fallthrough
		case openflow15.NXM_NX_REG3:
			fallthrough
		case openflow15.NXM_NX_REG4:
			fallthrough
		case openflow15.NXM_NX_REG5:
			fallthrough
		case openflow15.NXM_NX_REG6:
			fallthrough
		case openflow15.NXM_NX_REG7:
			fallthrough
		case openflow15.NXM_NX_REG8:
			fallthrough
		case openflow15.NXM_NX_REG9:
			fallthrough
		case openflow15.NXM_NX_REG10:
			fallthrough
		case openflow15.NXM_NX_REG11:
			fallthrough
		case openflow15.NXM_NX_REG12:
			fallthrough
		case openflow15.NXM_NX_REG13:
			fallthrough
		case openflow15.NXM_NX_REG14:
			fallthrough
		case openflow15.NXM_NX_REG15:
			reg, _ := getNXReg(m.MatchField)
			return reg
		}
		value := v.Data
		if !m.HasMask {
			return value
		}
		return &Uint32WithMask{
			Value: value,
			Mask:  m.Mask.(*openflow15.Uint32Message).Data,
		}
	case *openflow15.ByteArrayField:
		value := v.Data
		if !m.HasMask {
			return value
		}
		return &DataWithMask{
			Value: value,
			Mask:  m.Mask.(*openflow15.ByteArrayField).Data,
		}
	case *openflow15.CTLabel:
		value := v.Data[:]
		if !m.HasMask {
			return value
		}
		return &DataWithMask{
			Value: value,
			Mask:  m.Mask.(*openflow15.CTLabel).Data[:],
		}
	}
	return nil
}

func NewMatchField(mf *openflow15.MatchField) *MatchField {
	m := &MatchField{
		MatchField: mf,
	}
	m.name, m.nickName = getFieldNames(mf)
	return m
}

func getFieldNames(mf *openflow15.MatchField) (string, string) {
	var fieldName string
	var nickName string
	switch mf.Class {
	case openflow15.OXM_CLASS_NXM_0:
		switch mf.Field {
		case openflow15.NXM_OF_IN_PORT:
			fieldName = "NXM_OF_IN_PORT"
			nickName = "in_port"
		case openflow15.NXM_OF_ETH_DST:
			fieldName = "NXM_OF_ETH_DST"
			nickName = "dl_src"
		case openflow15.NXM_OF_ETH_SRC:
			fieldName = "NXM_OF_ETH_SRC"
			nickName = "dl_dst"
		case openflow15.NXM_OF_ETH_TYPE:
			fieldName = "NXM_OF_ETH_TYPE"
			nickName = "eth_type"
		case openflow15.NXM_OF_VLAN_TCI:
			fieldName = "NXM_OF_VLAN_TCI"
			nickName = "vlan_tci"
		case openflow15.NXM_OF_IP_TOS:
			fieldName = "NXM_OF_IP_TOS"
			nickName = "nw_tos"
		case openflow15.NXM_OF_IP_PROTO:
			fieldName = "NXM_OF_IP_PROTO"
			nickName = "ip_proto"
		case openflow15.NXM_OF_IP_SRC:
			fieldName = "NXM_OF_IP_SRC"
			nickName = "nw_src"
		case openflow15.NXM_OF_IP_DST:
			fieldName = "NXM_OF_IP_DST"
			nickName = "nw_dst"
		case openflow15.NXM_OF_TCP_SRC:
			fieldName = "NXM_OF_TCP_SRC"
			nickName = "tp_src"
		case openflow15.NXM_OF_TCP_DST:
			fieldName = "NXM_OF_TCP_DST"
			nickName = "tp_dst"
		case openflow15.NXM_OF_UDP_SRC:
			fieldName = "NXM_OF_UDP_SRC"
			nickName = "tp_src"
		case openflow15.NXM_OF_UDP_DST:
			fieldName = "NXM_OF_UDP_DST"
			nickName = "tp_dst"
		case openflow15.NXM_OF_ICMP_TYPE:
			fieldName = "NXM_OF_ICMP_TYPE"
			nickName = "icmp_type"
		case openflow15.NXM_OF_ICMP_CODE:
			fieldName = "NXM_OF_ICMP_CODE"
			nickName = "icmp_code"
		case openflow15.NXM_OF_ARP_OP:
			fieldName = "NXM_OF_ARP_OP"
			nickName = "arp_op"
		case openflow15.NXM_OF_ARP_SPA:
			fieldName = "NXM_OF_ARP_SPA"
			nickName = "arp_spa"
		case openflow15.NXM_OF_ARP_TPA:
			fieldName = "NXM_OF_ARP_TPA"
			nickName = "arp_tpa"
		}
	case openflow15.OXM_CLASS_NXM_1:
		switch mf.Field {
		case openflow15.NXM_NX_REG0:
			fallthrough
		case openflow15.NXM_NX_REG1:
			fallthrough
		case openflow15.NXM_NX_REG2:
			fallthrough
		case openflow15.NXM_NX_REG3:
			fallthrough
		case openflow15.NXM_NX_REG4:
			fallthrough
		case openflow15.NXM_NX_REG5:
			fallthrough
		case openflow15.NXM_NX_REG6:
			fallthrough
		case openflow15.NXM_NX_REG7:
			fallthrough
		case openflow15.NXM_NX_REG8:
			fallthrough
		case openflow15.NXM_NX_REG9:
			fallthrough
		case openflow15.NXM_NX_REG10:
			fallthrough
		case openflow15.NXM_NX_REG11:
			fallthrough
		case openflow15.NXM_NX_REG12:
			fallthrough
		case openflow15.NXM_NX_REG13:
			fallthrough
		case openflow15.NXM_NX_REG14:
			fallthrough
		case openflow15.NXM_NX_REG15:
			fieldName = fmt.Sprintf("NXM_NX_REG%d", mf.Field)
			nickName = fmt.Sprintf("reg%d", mf.Field)
		case openflow15.NXM_NX_TUN_ID:
			fieldName = "NXM_NX_TUN_ID"
			nickName = "tunnel_id"
		case openflow15.NXM_NX_ARP_SHA:
			fieldName = "NXM_NX_ARP_SHA"
			nickName = "arp_sha"
		case openflow15.NXM_NX_ARP_THA:
			fieldName = "NXM_NX_ARP_THA"
			nickName = "arp_tha"
		case openflow15.NXM_NX_IPV6_SRC:
			fieldName = "NXM_NX_IPV6_SRC"
			nickName = "ipv6_src"
		case openflow15.NXM_NX_IPV6_DST:
			fieldName = "NXM_NX_IPV6_DST"
			nickName = "ipv6_dst"
		case openflow15.NXM_NX_ICMPV6_TYPE:
			fieldName = "NXM_NX_ICMPV6_TYPE"
			nickName = "icmpv6_type"
		case openflow15.NXM_NX_ICMPV6_CODE:
			fieldName = "NXM_NX_ICMPV6_CODE"
			nickName = "icmpv6_code"
		case openflow15.NXM_NX_ND_TARGET:
			fieldName = "NXM_NX_ND_TARGET"
			nickName = "nd_target"
		case openflow15.NXM_NX_ND_SLL:
			fieldName = "NXM_NX_ND_SLL"
			nickName = "nd_sll"
		case openflow15.NXM_NX_ND_TLL:
			fieldName = "NXM_NX_ND_TLL"
			nickName = "nd_tll"
		case openflow15.NXM_NX_IP_FRAG:
			fieldName = "NXM_NX_IP_FRAG"
			nickName = "ip_frag"
		case openflow15.NXM_NX_IPV6_LABEL:
			fieldName = "NXM_NX_IPV6_LABEL"
			nickName = "ipv6_label"
		case openflow15.NXM_NX_IP_ECN:
			fieldName = "NXM_NX_IP_ECN"
			nickName = "ip_ecn"
		case openflow15.NXM_NX_IP_TTL:
			fieldName = "NXM_NX_IP_TTL"
			nickName = "nw_ttl"
		case openflow15.NXM_NX_MPLS_TTL:
			fieldName = "NXM_NX_MPLS_TTL"
			nickName = "mpls_ttl"
		case openflow15.NXM_NX_TUN_IPV4_SRC:
			fieldName = "NXM_NX_TUN_IPV4_SRC"
			nickName = "nw_src"
		case openflow15.NXM_NX_TUN_IPV4_DST:
			fieldName = "NXM_NX_TUN_IPV4_DST"
			nickName = "nw_dst"
		case openflow15.NXM_NX_PKT_MARK:
			fieldName = "NXM_NX_PKT_MARK"
			nickName = "pkt_mark"
		case openflow15.NXM_NX_TCP_FLAGS:
			fieldName = "NXM_NX_TCP_FLAGS"
			nickName = "tcp_flags"
		case openflow15.NXM_NX_CONJ_ID:
			fieldName = "NXM_NX_CONJ_ID"
			nickName = "conj_id"
		case openflow15.NXM_NX_TUN_GBP_ID:
			fieldName = "NXM_NX_TUN_GBP_ID"
			nickName = "tun_gbp_id"
		case openflow15.NXM_NX_TUN_GBP_FLAGS:
			fieldName = "NXM_NX_TUN_GBP_FLAGS"
			nickName = "tun_gbp_flags"
		case openflow15.NXM_NX_TUN_FLAGS:
			fieldName = "NXM_NX_TUN_FLAGS"
			nickName = "tun_flags"
		case openflow15.NXM_NX_CT_STATE:
			fieldName = "NXM_NX_CT_STATE"
			nickName = "ct_state"
		case openflow15.NXM_NX_CT_ZONE:
			fieldName = "NXM_NX_CT_ZONE"
			nickName = "ct_zone"
		case openflow15.NXM_NX_CT_MARK:
			fieldName = "NXM_NX_CT_MARK"
			nickName = "ct_mark"
		case openflow15.NXM_NX_CT_LABEL:
			fieldName = "NXM_NX_CT_LABEL"
			nickName = "ct_label"
		case openflow15.NXM_NX_TUN_IPV6_SRC:
			fieldName = "NXM_NX_TUN_IPV6_SRC"
			nickName = "tun_ipv6_src"
		case openflow15.NXM_NX_TUN_IPV6_DST:
			fieldName = "NXM_NX_TUN_IPV6_DST"
			nickName = "tun_ipv6_dst"
		case openflow15.NXM_NX_TUN_METADATA0:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA1:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA2:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA3:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA4:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA5:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA6:
			fallthrough
		case openflow15.NXM_NX_TUN_METADATA7:
			num := mf.Field - openflow15.NXM_NX_TUN_METADATA0
			fieldName = fmt.Sprintf("NXM_NX_TUN_METADATA%d", num)
			nickName = fmt.Sprintf("tun_metadata%d", num)
		case openflow15.NXM_NX_CT_NW_PROTO:
			fieldName = "NXM_NX_CT_NW_PROTO"
			nickName = "ct_nw_proto"
		case openflow15.NXM_NX_CT_NW_SRC:
			fieldName = "NXM_NX_CT_NW_SRC"
			nickName = "ct_nw_src"
		case openflow15.NXM_NX_CT_NW_DST:
			fieldName = "NXM_NX_CT_NW_DST"
			nickName = "ct_nw_dst"
		case openflow15.NXM_NX_CT_IPV6_SRC:
			fieldName = "NXM_NX_CT_IPV6_SRC"
			nickName = "ct_ipv6_src"
		case openflow15.NXM_NX_CT_IPV6_DST:
			fieldName = "NXM_NX_CT_IPV6_DST"
			nickName = "ct_ipv6_dst"
		case openflow15.NXM_NX_CT_TP_SRC:
			fieldName = "NXM_NX_CT_TP_SRC"
			nickName = "ct_tp_src"
		case openflow15.NXM_NX_CT_TP_DST:
			fieldName = "NXM_NX_CT_TP_DST"
			nickName = "ct_tp_dst"
		}
	case openflow15.OXM_CLASS_OPENFLOW_BASIC:
		switch mf.Field {
		case openflow15.OXM_FIELD_IN_PORT:
			fieldName = "OXM_OF_IN_PORT"
			nickName = "in_port"
		case openflow15.OXM_FIELD_IN_PHY_PORT:
			fieldName = "OXM_OF_IN_PHY_PORT"
			nickName = "phy_in_port"
		case openflow15.OXM_FIELD_METADATA:
			fieldName = "OXM_OF_METADATA"
			nickName = "metadata"
		case openflow15.OXM_FIELD_ETH_DST:
			fieldName = "OXM_OF_ETH_DST"
			nickName = "dl_dst"
		case openflow15.OXM_FIELD_ETH_SRC:
			fieldName = "OXM_OF_ETH_SRC"
			nickName = "dl_src"
		case openflow15.OXM_FIELD_ETH_TYPE:
			fieldName = "OXM_OF_ETH_TYPE"
			nickName = "ether_type"
		case openflow15.OXM_FIELD_VLAN_VID:
			fieldName = "OXM_OF_VLAN_VID"
			nickName = "vlan_vid"
		case openflow15.OXM_FIELD_VLAN_PCP:
			fieldName = "OXM_OF_VLAN_PCP"
			nickName = "vlan_pcp"
		case openflow15.OXM_FIELD_IP_DSCP:
			fieldName = "OXM_OF_IP_DSCP"
			nickName = "ip_dscp"
		case openflow15.OXM_FIELD_IP_ECN:
			fieldName = "OXM_OF_IP_ECN"
			nickName = "ip_ecn"
		case openflow15.OXM_FIELD_IP_PROTO:
			fieldName = "OXM_OF_IP_PROTO"
			nickName = "ip_proto"
		case openflow15.OXM_FIELD_IPV4_SRC:
			fieldName = "OXM_OF_IPV4_SRC"
			nickName = "nw_src"
		case openflow15.OXM_FIELD_IPV4_DST:
			fieldName = "OXM_OF_IPV4_DST"
			nickName = "nw_dst"
		case openflow15.OXM_FIELD_TCP_SRC:
			fieldName = "OXM_OF_TCP_SRC"
			nickName = "tp_src"
		case openflow15.OXM_FIELD_TCP_DST:
			fieldName = "OXM_OF_TCP_DST"
			nickName = "tp_dst"
		case openflow15.OXM_FIELD_UDP_SRC:
			fieldName = "OXM_OF_UDP_SRC"
			nickName = "udp_src"
		case openflow15.OXM_FIELD_UDP_DST:
			fieldName = "OXM_OF_UDP_DST"
			nickName = "udp_dst"
		case openflow15.OXM_FIELD_SCTP_SRC:
			fieldName = "OXM_OF_SCTP_SRC"
			nickName = "sctp_src"
		case openflow15.OXM_FIELD_SCTP_DST:
			fieldName = "OXM_OF_SCTP_DST"
			nickName = "sctp_dst"
		case openflow15.OXM_FIELD_ICMPV4_TYPE:
			fieldName = "OXM_OF_ICMPV4_TYPE"
			nickName = "icmp_type"
		case openflow15.OXM_FIELD_ICMPV4_CODE:
			fieldName = "OXM_OF_ICMPV4_CODE"
			nickName = "icmp_code"
		case openflow15.OXM_FIELD_ARP_OP:
			fieldName = "OXM_OF_ARP_OP"
			nickName = "arp_op"
		case openflow15.OXM_FIELD_ARP_SPA:
			fieldName = "OXM_OF_ARP_SPA"
			nickName = "arp_spa"
		case openflow15.OXM_FIELD_ARP_TPA:
			fieldName = "OXM_OF_ARP_TPA"
			nickName = "arp_tpa"
		case openflow15.OXM_FIELD_ARP_SHA:
			fieldName = "OXM_OF_ARP_SHA"
			nickName = "arp_sha"
		case openflow15.OXM_FIELD_ARP_THA:
			fieldName = "OXM_OF_ARP_THA"
			nickName = "arp_thp"
		case openflow15.OXM_FIELD_IPV6_SRC:
			fieldName = "OXM_OF_IPV6_SRC"
			nickName = "ipv6_src"
		case openflow15.OXM_FIELD_IPV6_DST:
			fieldName = "OXM_OF_IPV6_DST"
			nickName = "ipv6_dst"
		case openflow15.OXM_FIELD_IPV6_FLABEL:
			fieldName = "OXM_OF_IPV6_FLABEL"
			nickName = "ipv6_label"
		case openflow15.OXM_FIELD_ICMPV6_TYPE:
			fieldName = "OXM_OF_ICMPV6_TYPE"
			nickName = "icmpv6_type"
		case openflow15.OXM_FIELD_ICMPV6_CODE:
			fieldName = "OXM_OF_ICMPV6_CODE"
			nickName = "icmpv6_code"
		case openflow15.OXM_FIELD_IPV6_ND_TARGET:
			fieldName = "OXM_OF_IPV6_ND_TARGET"
			nickName = "ipv6_nd_target"
		case openflow15.OXM_FIELD_IPV6_ND_SLL:
			fieldName = "OXM_OF_IPV6_ND_SLL"
			nickName = "ipv6_nd_sll"
		case openflow15.OXM_FIELD_IPV6_ND_TLL:
			fieldName = "OXM_OF_IPV6_ND_TLL"
			nickName = "ipv6_nd_tll"
		case openflow15.OXM_FIELD_MPLS_LABEL:
			fieldName = "OXM_OF_MPLS_LABEL"
			nickName = "mpls_label"
		case openflow15.OXM_FIELD_MPLS_TC:
			fieldName = "OXM_OF_MPLS_TC"
			nickName = "mpls_tc"
		case openflow15.OXM_FIELD_MPLS_BOS:
			fieldName = "OXM_OF_MPLS_BOS"
			nickName = "mpls_bos"
		case openflow15.OXM_FIELD_PBB_ISID:
			fieldName = "OXM_OF_PBB_ISID"
			nickName = "pbb_isid"
		case openflow15.OXM_FIELD_TUNNEL_ID:
			fieldName = "OXM_OF_TUNNEL_ID"
			nickName = "tunnel_id"
		case openflow15.OXM_FIELD_IPV6_EXTHDR:
			fieldName = "OXM_OF_IPV6_EXTHDR"
			nickName = "ipv6_exthdr"
		}
	case openflow15.OXM_CLASS_PACKET_REGS:
		switch mf.Field {
		case openflow15.OXM_PACKET_REG0:
			fieldName = "OXM_OF_PACKET_REG0"
			nickName = "xreg0"
		case openflow15.OXM_PACKET_REG1:
			fieldName = "OXM_OF_PACKET_REG1"
			nickName = "xreg1"
		case openflow15.OXM_PACKET_REG2:
			fieldName = "OXM_OF_PACKET_REG2"
			nickName = "xreg2"
		case openflow15.OXM_PACKET_REG3:
			fieldName = "OXM_OF_PACKET_REG3"
			nickName = "xreg3"
		case openflow15.OXM_PACKET_REG4:
			fieldName = "OXM_OF_PACKET_REG4"
			nickName = "xreg4"
		case openflow15.OXM_PACKET_REG5:
			fieldName = "OXM_OF_PACKET_REG5"
			nickName = "xreg5"
		case openflow15.OXM_PACKET_REG6:
			fieldName = "OXM_OF_PACKET_REG6"
			nickName = "xreg6"
		case openflow15.OXM_PACKET_REG7:
			fieldName = "OXM_OF_PACKET_REG7"
			nickName = "xreg7"
		}
	}
	return fieldName, nickName
}

func getCTState(mf *openflow15.MatchField) (*CTStatesChecker, error) {
	data, err := getUint32(mf.Value)
	if err != nil {
		return nil, err
	}
	mask, err := getUint32(mf.Mask)
	if err != nil {
		return nil, err
	}
	return &CTStatesChecker{Value: data, Mask: mask}, nil
}

func getUint8(value util.Message) (uint8, error) {
	data, err := value.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func getUint16(value util.Message) (uint16, error) {
	data, err := value.MarshalBinary()
	if err != nil {
		return 0, err
	}
	if len(data) < 2 {
		return 0, errors.New("the field value has wrong size to translate to uint16")
	}
	return binary.BigEndian.Uint16(data), nil
}

func getUint32(value util.Message) (uint32, error) {
	data, err := value.MarshalBinary()
	if err != nil {
		return 0, err
	}
	if len(data) < 4 {
		return 0, errors.New("the field value has wrong size to translate to uint32")
	}
	return binary.BigEndian.Uint32(data), nil
}

func getNXReg(mf *openflow15.MatchField) (*NXRegister, error) {
	value := mf.Value
	data, err := getUint32(value)
	if err != nil {
		return nil, err
	}

	id := int(mf.Field)
	reg := &NXRegister{
		ID:   id,
		Data: data,
	}
	if mf.HasMask {
		maskData, err := getUint32(mf.Mask)
		if err != nil {
			return nil, err
		}
		rng := getNXRangeFromUint32Mask(maskData)
		reg.Range = rng
		reg.Mask = maskData
	}
	return reg, nil
}

func getNXRangeFromUint32Mask(mask uint32) *openflow15.NXRange {
	leftMask := uint32(0x80000000)
	rightMask := uint32(0x1)
	maxLength := 32

	i := 0
	var start, end int
	for i < maxLength {
		if mask<<i&leftMask != 0 {
			end = 31 - i
			break
		}
		i++
	}
	i = 0
	for i < maxLength {
		if mask>>i&rightMask != 0 {
			start = i
			break
		}
		i++
	}
	return openflow15.NewNXRange(start, end)
}

func GetUint32ValueWithRange(data uint32, rng *openflow15.NXRange) uint32 {
	start := rng.GetOfs()
	end := start + rng.GetNbits()
	leftOfs := 32 - end
	return data << leftOfs >> (start + leftOfs)
}

func GetUint64ValueWithRange(data uint64, rng *openflow15.NXRange) uint64 {
	start := rng.GetOfs()
	end := start + rng.GetNbits()
	leftOfs := 64 - end
	return data << leftOfs >> (start + leftOfs)
}

func GetUint32ValueWithRangeFromBytes(data []byte, rng *openflow15.NXRange) (uint32, error) {
	if len(data) <= 4 {
		uint32Data := binary.BigEndian.Uint32(data)
		return GetUint32ValueWithRange(uint32Data, rng), nil
	}
	startByte := int(rng.GetOfs() / 8)
	startDiff := startByte * 8
	endByte := int((rng.GetNbits() + 7) / 8)
	if endByte > len(data) {
		return 0, errors.New("range is larger than data length")
	}
	uint32Data := binary.BigEndian.Uint32(data[startByte:endByte])
	newRange := openflow15.NewNXRange(int(rng.GetOfs())-startDiff, int(rng.GetNbits())-startDiff)
	return GetUint32ValueWithRange(uint32Data, newRange), nil
}

func GetUint64ValueWithRangeFromBytes(data []byte, rng *openflow15.NXRange) (uint64, error) {
	if len(data) <= 8 {
		uint64Data := binary.BigEndian.Uint64(data)
		return GetUint64ValueWithRange(uint64Data, rng), nil
	}
	startByte := int(rng.GetOfs() / 8)
	startDiff := startByte * 8
	endByte := int((rng.GetNbits() + 7) / 8)
	if endByte > len(data) {
		return 0, errors.New("range is larger than data length")
	}
	uint64Data := binary.BigEndian.Uint64(data[startByte:endByte])
	newRange := openflow15.NewNXRange(int(rng.GetOfs())-startDiff, int(rng.GetNbits())-startDiff)
	return GetUint64ValueWithRange(uint64Data, newRange), nil
}

type PortField struct {
	Port uint16
}

func (m *PortField) Len() uint16 {
	return 2
}
func (m *PortField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint16(data, m.Port)
	return
}

func (m *PortField) UnmarshalBinary(data []byte) error {
	m.Port = binary.BigEndian.Uint16(data)
	return nil
}

type ProtocolField struct {
	Protocol uint8
}

func (m *ProtocolField) Len() uint16 {
	return 1
}
func (m *ProtocolField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = m.Protocol
	return
}

func (m *ProtocolField) UnmarshalBinary(data []byte) error {
	m.Protocol = data[0]
	return nil
}
