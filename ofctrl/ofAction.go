package ofctrl

import (
	"errors"
	"fmt"
	"net"

	"antrea.io/libOpenflow/openflow13"
)

const (
	ActTypePushVlan       = "pushVlan"
	ActTypeSetVlan        = "setVlan"
	ActTypePopVlan        = "popVlan"
	ActTypePopMpls        = "popMpls"
	ActTypePushMpls       = "pushMpls"
	ActTypeSetDstMac      = "setMacDa"
	ActTypeSetSrcMac      = "setMacSa"
	ActTypeSetTunnelID    = "setTunnelId"
	ActTypeSetMetadata    = "setMetadata"   // use set_field
	ActTypeWriteMetadata  = "writeMetadata" // use writeMetadata instruction
	ActTypeSetSrcIP       = "setIPSa"
	ActTypeSetDstIP       = "setIPDa"
	ActTypeSetTunnelSrcIP = "setTunSa"
	ActTypeSetTunnelDstIP = "setTunDa"
	ActTypeSetDSCP        = "setDscp"
	ActTypeSetARPOper     = "setARPOper"
	ActTypeSetARPSHA      = "setARPSha"
	ActTypeSetARPTHA      = "setARPTha"
	ActTypeSetARPSPA      = "setARPSpa"
	ActTypeSetARPTPA      = "setARPTpa"
	ActTypeSetTCPsPort    = "setTCPSrc"
	ActTypeSetTCPdPort    = "setTCPDst"
	ActTypeSetTCPFlags    = "setTCPFlags"
	ActTypeSetUDPsPort    = "setUDPSrc"
	ActTypeSetUDPdPort    = "setUDPDst"
	ActTypeSetSCTPsPort   = "setSCTPSrc"
	ActTypeSetSCTPdPort   = "setSCTPDst"
	ActTypeSetNDTarget    = "setNDTarget"
	ActTypeSetNDSLL       = "setNDSLL"
	ActTypeSetNDTLL       = "setNDTLL"
	ActTypeSetICMP6Type   = "setICMPv6Type"
	ActTypeSetICMP6Code   = "setICMPv6Code"
	ActTypeSetICMP4Type   = "setICMPv4Type"
	ActTypeSetICMP4Code   = "setICMPv4Code"
	ActTypeNXLoad         = "loadReg"
	ActTypeNXMove         = "moveReg"
	ActTypeNXCT           = "ct"
	ActTypeNXConjunction  = "conjunction"
	ActTypeDecTTL         = "decTTL"
	ActTypeNXResubmit     = "resubmit"
	ActTypeGroup          = "group"
	ActTypeNXLearn        = "learn"
	ActTypeNXNote         = "note"
	ActTypeController     = "controller"
	ActTypeOutput         = "output"
	ActTypeNXOutput       = "nxOutput"
)

type OFAction interface {
	GetActionMessage() openflow13.Action
	GetActionType() string
}

type PushVLANAction struct {
	EtherType uint16
}

func (a *PushVLANAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionPushVlan(a.EtherType)
}

func (a *PushVLANAction) GetActionType() string {
	return ActTypePushVlan
}

type SetVLANAction struct {
	VlanID uint16
}

func (a *SetVLANAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewVlanIdField(a.VlanID, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetVLANAction) GetActionType() string {
	return ActTypeSetVlan
}

type PopMPLSAction struct {
	EtherType uint16
}

func (a *PopMPLSAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionPopMpls(a.EtherType)
}

func (a *PopMPLSAction) GetActionType() string {
	return ActTypePopMpls
}

type PushMPLSAction struct {
	EtherType uint16
}

func (a *PushMPLSAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionPushMpls(a.EtherType)
}

func (a *PushMPLSAction) GetActionType() string {
	return ActTypePushMpls
}

type PopVLANAction struct {
}

func (a *PopVLANAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionPopVlan()
}

func (a *PopVLANAction) GetActionType() string {
	return ActTypePopVlan
}

type SetSrcMACAction struct {
	MAC net.HardwareAddr
}

func (a *SetSrcMACAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewEthSrcField(a.MAC, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSrcMACAction) GetActionType() string {
	return ActTypeSetSrcMac
}

type SetDstMACAction struct {
	MAC net.HardwareAddr
}

func (a *SetDstMACAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewEthDstField(a.MAC, nil)
	return openflow13.NewActionSetField(*field)
}

func (a *SetDstMACAction) GetActionType() string {
	return ActTypeSetDstMac
}

type SetTunnelIDAction struct {
	TunnelID uint64
}

func (a *SetTunnelIDAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTunnelIdField(a.TunnelID)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTunnelIDAction) GetActionType() string {
	return ActTypeSetTunnelID
}

type SetMetadataAction struct {
	Metadata     uint64
	MetadataMask *uint64
}

func (a *SetMetadataAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewMetadataField(a.Metadata, a.MetadataMask)
	return openflow13.NewActionSetField(*field)
}

func (a *SetMetadataAction) GetActionType() string {
	return ActTypeSetMetadata
}

type SetTunnelDstAction struct {
	IP net.IP
}

func (a *SetTunnelDstAction) GetActionMessage() openflow13.Action {
	var field *openflow13.MatchField
	if a.IP.To4() == nil {
		field = NewTunnelIpv6DstField(a.IP, nil)
	} else {
		field = openflow13.NewTunnelIpv4DstField(a.IP, nil)
	}
	return openflow13.NewActionSetField(*field)
}

func NewTunnelIpv6DstField(tunnelIpDst net.IP, tunnelIpDstMask *net.IP) *openflow13.MatchField {
	f := new(openflow13.MatchField)
	f.Class = openflow13.OXM_CLASS_NXM_1
	f.Field = openflow13.NXM_NX_TUN_IPV6_DST
	f.HasMask = false

	ipDstField := new(openflow13.Ipv6DstField)
	ipDstField.Ipv6Dst = tunnelIpDst
	f.Value = ipDstField
	f.Length = uint8(ipDstField.Len())

	// Add the mask
	if tunnelIpDstMask != nil {
		mask := new(openflow13.Ipv6DstField)
		mask.Ipv6Dst = *tunnelIpDstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

func NewTunnelIpv6SrcField(tunnelIpSrc net.IP, tunnelIpSrcMask *net.IP) *openflow13.MatchField {
	f := new(openflow13.MatchField)
	f.Class = openflow13.OXM_CLASS_NXM_1
	f.Field = openflow13.NXM_NX_TUN_IPV6_SRC
	f.HasMask = false

	ipSrcField := new(openflow13.Ipv6SrcField)
	ipSrcField.Ipv6Src = tunnelIpSrc
	f.Value = ipSrcField
	f.Length = uint8(ipSrcField.Len())

	// Add the mask
	if tunnelIpSrcMask != nil {
		mask := new(openflow13.Ipv6SrcField)
		mask.Ipv6Src = *tunnelIpSrcMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

func (a *SetTunnelDstAction) GetActionType() string {
	return ActTypeSetTunnelDstIP
}

type SetTunnelSrcAction struct {
	IP net.IP
}

func (a *SetTunnelSrcAction) GetActionMessage() openflow13.Action {
	var field *openflow13.MatchField
	if a.IP.To4() == nil {
		field = NewTunnelIpv6SrcField(a.IP, nil)
	} else {
		field = openflow13.NewTunnelIpv4SrcField(a.IP, nil)
	}
	return openflow13.NewActionSetField(*field)
}

func (a *SetTunnelSrcAction) GetActionType() string {
	return ActTypeSetTunnelSrcIP
}

type SetDstIPAction struct {
	IP     net.IP
	IPMask *net.IP
}

func (a *SetDstIPAction) GetActionMessage() openflow13.Action {
	var field *openflow13.MatchField
	if a.IP.To4() == nil {
		field = openflow13.NewIpv6DstField(a.IP, a.IPMask)
	} else {
		field = openflow13.NewIpv4DstField(a.IP, a.IPMask)
	}
	return openflow13.NewActionSetField(*field)
}

func (a *SetDstIPAction) GetActionType() string {
	return ActTypeSetDstIP
}

type SetSrcIPAction struct {
	IP     net.IP
	IPMask *net.IP
}

func (a *SetSrcIPAction) GetActionMessage() openflow13.Action {
	var field *openflow13.MatchField
	if a.IP.To4() == nil {
		field = openflow13.NewIpv6SrcField(a.IP, a.IPMask)
	} else {
		field = openflow13.NewIpv4SrcField(a.IP, a.IPMask)
	}
	return openflow13.NewActionSetField(*field)
}

func (a *SetSrcIPAction) GetActionType() string {
	return ActTypeSetSrcIP
}

type SetDSCPAction struct {
	Value uint8
}

func (a *SetDSCPAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewIpDscpField(a.Value)
	return openflow13.NewActionSetField(*field)
}

func (a *SetDSCPAction) GetActionType() string {
	return ActTypeSetDSCP
}

type SetARPOpAction struct {
	Value uint16
}

func (a *SetARPOpAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpOperField(a.Value)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPOpAction) GetActionType() string {
	return ActTypeSetARPOper
}

type SetARPShaAction struct {
	MAC net.HardwareAddr
}

func (a *SetARPShaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpShaField(a.MAC)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPShaAction) GetActionType() string {
	return ActTypeSetARPSHA
}

type SetARPThaAction struct {
	MAC net.HardwareAddr
}

func (a *SetARPThaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpThaField(a.MAC)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPThaAction) GetActionType() string {
	return ActTypeSetARPTHA
}

type SetARPSpaAction struct {
	IP net.IP
}

func (a *SetARPSpaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpSpaField(a.IP)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPSpaAction) GetActionType() string {
	return ActTypeSetARPSPA
}

type SetARPTpaAction struct {
	IP net.IP
}

func (a *SetARPTpaAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewArpTpaField(a.IP)
	return openflow13.NewActionSetField(*field)
}

func (a *SetARPTpaAction) GetActionType() string {
	return ActTypeSetARPTPA
}

type SetTCPSrcPortAction struct {
	Port uint16
}

func (a *SetTCPSrcPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTcpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTCPSrcPortAction) GetActionType() string {
	return ActTypeSetTCPsPort
}

type SetTCPDstPortAction struct {
	Port uint16
}

func (a *SetTCPDstPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTcpDstField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTCPDstPortAction) GetActionType() string {
	return ActTypeSetTCPdPort
}

type SetTCPFlagsAction struct {
	Flags    uint16
	FlagMask *uint16
}

func (a *SetTCPFlagsAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewTcpFlagsField(a.Flags, a.FlagMask)
	return openflow13.NewActionSetField(*field)
}

func (a *SetTCPFlagsAction) GetActionType() string {
	return ActTypeSetTCPFlags
}

type SetUDPSrcPortAction struct {
	Port uint16
}

func (a *SetUDPSrcPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewUdpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetUDPSrcPortAction) GetActionType() string {
	return ActTypeSetUDPsPort
}

type SetUDPDstPortAction struct {
	Port uint16
}

func (a *SetUDPDstPortAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewUdpDstField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetUDPDstPortAction) GetActionType() string {
	return ActTypeSetUDPdPort
}

type SetSCTPSrcAction struct {
	Port uint16
}

func (a *SetSCTPSrcAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewSctpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSCTPSrcAction) GetActionType() string {
	return ActTypeSetSCTPsPort
}

type SetSCTPDstAction struct {
	Port uint16
}

func (a *SetSCTPDstAction) GetActionMessage() openflow13.Action {
	field := openflow13.NewSctpSrcField(a.Port)
	return openflow13.NewActionSetField(*field)
}

func (a *SetSCTPDstAction) GetActionType() string {
	return ActTypeSetSCTPdPort
}

type NXLoadAction struct {
	Field *openflow13.MatchField
	Value uint64
	Range *openflow13.NXRange
}

func (a *NXLoadAction) GetActionMessage() openflow13.Action {
	ofsNbits := a.Range.ToOfsBits()
	return openflow13.NewNXActionRegLoad(ofsNbits, a.Field, a.Value)
}

func (a *NXLoadAction) GetActionType() string {
	return ActTypeNXLoad
}

func (a *NXLoadAction) ResetFieldLength(ofSwitch *OFSwitch) {
	ResetFieldLength(a.Field, ofSwitch.tlvMgr.status)
}

func NewNXLoadAction(fieldName string, data uint64, dataRange *openflow13.NXRange) (*NXLoadAction, error) {
	field, err := openflow13.FindFieldHeaderByName(fieldName, true)
	if err != nil {
		return nil, err
	}
	return &NXLoadAction{
		Field: field,
		Range: dataRange,
		Value: data,
	}, nil
}

type NXMoveAction struct {
	SrcField  *openflow13.MatchField
	DstField  *openflow13.MatchField
	SrcStart  uint16
	DstStart  uint16
	MoveNbits uint16
}

func (a *NXMoveAction) GetActionMessage() openflow13.Action {
	return openflow13.NewNXActionRegMove(a.MoveNbits, a.SrcStart, a.DstStart, a.SrcField, a.DstField)
}

func (a *NXMoveAction) GetActionType() string {
	return ActTypeNXMove
}

func (a *NXMoveAction) ResetFieldsLength(ofSwitch *OFSwitch) {
	ResetFieldLength(a.SrcField, ofSwitch.tlvMgr.status)
	ResetFieldLength(a.DstField, ofSwitch.tlvMgr.status)
}

func NewNXMoveAction(srcName string, dstName string, srcRange *openflow13.NXRange, dstRange *openflow13.NXRange) (*NXMoveAction, error) {
	srcNBits := srcRange.GetNbits()
	srcOfs := srcRange.GetOfs()
	srcField, err := openflow13.FindFieldHeaderByName(srcName, false)
	if err != nil {
		return nil, err
	}
	dstNBits := dstRange.GetNbits()
	dstOfs := dstRange.GetOfs()
	dstField, err := openflow13.FindFieldHeaderByName(dstName, false)
	if err != nil {
		return nil, err
	}
	if srcNBits != dstNBits {
		return nil, fmt.Errorf("bits count for move opereation is inconsistent, src: %d, dst: %d", srcNBits, dstNBits)
	}
	return &NXMoveAction{
		SrcField:  srcField,
		DstField:  dstField,
		SrcStart:  srcOfs,
		DstStart:  dstOfs,
		MoveNbits: srcNBits,
	}, nil
}

type NXConnTrackAction struct {
	commit       bool
	force        bool
	table        *uint8
	zoneImm      *uint16
	zoneSrcField *openflow13.MatchField
	zoneSrcRange *openflow13.NXRange
	actions      []openflow13.Action
}

func (a *NXConnTrackAction) GetActionMessage() openflow13.Action {
	ctAction := openflow13.NewNXActionConnTrack()
	if a.commit {
		ctAction.Commit()
	}
	if a.force {
		ctAction.Force()
	}
	if a.table != nil {
		ctAction.Table(*a.table)
	}
	if a.zoneSrcField != nil {
		ctAction.ZoneRange(a.zoneSrcField, a.zoneSrcRange)
	} else if a.zoneImm != nil {
		ctAction.ZoneImm(*a.zoneImm)
	}
	if a.actions != nil {
		ctAction = ctAction.AddAction(a.actions...)
	}
	return ctAction
}

func (a *NXConnTrackAction) GetActionType() string {
	return ActTypeNXCT
}

// This function only support immediate number for ct_zone
func NewNXConnTrackAction(commit bool, force bool, table *uint8, zone *uint16, actions ...openflow13.Action) *NXConnTrackAction {
	return &NXConnTrackAction{
		commit:  commit,
		force:   force,
		table:   table,
		zoneImm: zone,
		actions: actions,
	}
}

// This function support immediate number and field or subfield for ct_zone
func NewNXConnTrackActionWithZoneField(commit bool, force bool, table *uint8, zoneImm *uint16, zoneSrcFieldName string, zoneSrcRange *openflow13.NXRange, actions ...openflow13.Action) *NXConnTrackAction {
	var zoneSrc *openflow13.MatchField
	var zoneSrcRng *openflow13.NXRange
	if zoneSrcFieldName != "" {
		zoneSrc, _ = openflow13.FindFieldHeaderByName(zoneSrcFieldName, true)
		zoneSrcRng = zoneSrcRange
	}
	return &NXConnTrackAction{
		commit:       commit,
		force:        force,
		table:        table,
		zoneImm:      zoneImm,
		zoneSrcField: zoneSrc,
		zoneSrcRange: zoneSrcRng,
		actions:      actions,
	}
}

type NXConjunctionAction struct {
	ID      uint32
	Clause  uint8
	NClause uint8
}

func (a *NXConjunctionAction) GetActionMessage() openflow13.Action {
	return openflow13.NewNXActionConjunction(a.Clause, a.NClause, a.ID)
}

func (a *NXConjunctionAction) GetActionType() string {
	return ActTypeNXConjunction
}

func NewNXConjunctionAction(conjID uint32, clause uint8, nClause uint8) (*NXConjunctionAction, error) {
	if nClause < 2 || nClause > 64 {
		return nil, errors.New("clause number in conjunction shoule be in range [2,64]")
	}
	if clause > nClause {
		return nil, errors.New("clause in conjunction should be less than nclause")
	} else if clause < 1 {
		return nil, errors.New("clause in conjunction should be no less than 1")
	}
	return &NXConjunctionAction{
		ID:      conjID,
		Clause:  clause - 1,
		NClause: nClause,
	}, nil
}

type DecTTLAction struct {
}

func (a *DecTTLAction) GetActionMessage() openflow13.Action {
	return openflow13.NewActionDecNwTtl()
}

func (a *DecTTLAction) GetActionType() string {
	return ActTypeDecTTL
}

type NXNoteAction struct {
	Notes []byte
}

func (a *NXNoteAction) GetActionMessage() openflow13.Action {
	noteAction := openflow13.NewNXActionNote()
	noteAction.Note = a.Notes
	return noteAction
}

func (a *NXNoteAction) GetActionType() string {
	return ActTypeNXNote
}

type NXController struct {
	ControllerID uint16
	Reason       uint8
}

func (a *NXController) GetActionMessage() openflow13.Action {
	action := openflow13.NewNXActionController(a.ControllerID)
	action.MaxLen = 128
	action.Reason = a.Reason
	return action
}

func (a *NXController) GetActionType() string {
	return ActTypeController
}

type NXLoadXXRegAction struct {
	FieldNumber uint8
	Value       []byte
	Mask        []byte
}

func (a *NXLoadXXRegAction) GetActionMessage() openflow13.Action {
	fieldName := fmt.Sprintf("NXM_NX_XXREG%d", a.FieldNumber)
	field, _ := openflow13.FindFieldHeaderByName(fieldName, len(a.Mask) > 0)
	field.Value = &openflow13.ByteArrayField{Data: a.Value, Length: uint8(len(a.Value))}
	if field.HasMask {
		field.Mask = &openflow13.ByteArrayField{Data: a.Mask, Length: uint8(len(a.Mask))}
	}
	return openflow13.NewNXActionRegLoad2(field)
}

func (a *NXLoadXXRegAction) GetActionType() string {
	return ActTypeNXLoad
}

type SetNDTargetAction struct {
	Target net.IP
}

func (a *SetNDTargetAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_NX_ND_TARGET", false)
	field.Value = &openflow13.Ipv6DstField{Ipv6Dst: a.Target}
	return openflow13.NewActionSetField(*field)
}

func (a *SetNDTargetAction) GetActionType() string {
	return ActTypeSetNDTarget
}

type SetNDSLLAction struct {
	MAC net.HardwareAddr
}

func (a *SetNDSLLAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_NX_ND_SLL", false)
	field.Value = &openflow13.EthSrcField{EthSrc: a.MAC}
	return openflow13.NewActionSetField(*field)
}

func (a *SetNDSLLAction) GetActionType() string {
	return ActTypeSetNDSLL
}

type SetNDTLLAction struct {
	MAC net.HardwareAddr
}

func (a *SetNDTLLAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_NX_ND_TLL", false)
	field.Value = &openflow13.EthDstField{EthDst: a.MAC}
	return openflow13.NewActionSetField(*field)
}

func (a *SetNDTLLAction) GetActionType() string {
	return ActTypeSetNDTLL
}

type SetICMPv6TypeAction struct {
	Type uint8
}

func (a *SetICMPv6TypeAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_NX_ICMPV6_Type", false)
	field.Value = &openflow13.IcmpTypeField{Type: a.Type}
	return openflow13.NewActionSetField(*field)
}

func (a *SetICMPv6TypeAction) GetActionType() string {
	return ActTypeSetICMP6Type
}

type SetICMPv6CodeAction struct {
	Code uint8
}

func (a *SetICMPv6CodeAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_NX_ICMPV6_Code", false)
	field.Value = &openflow13.IcmpCodeField{Code: a.Code}
	return openflow13.NewActionSetField(*field)
}

func (a *SetICMPv6CodeAction) GetActionType() string {
	return ActTypeSetICMP6Code
}

// Currently, we only support Flow.Send() function to generate
// ICMP match/set flow message. We can also support Flow.Next()
// function to generate ICMP match/set flow message in future once
// libOpenflow support NewICMPXxxxField API.
type SetICMPv4TypeAction struct {
	Type uint8
}

func (a *SetICMPv4TypeAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_OF_ICMP_TYPE", false)
	field.Value = &openflow13.IcmpTypeField{Type: a.Type}
	return openflow13.NewActionSetField(*field)
}

func (a *SetICMPv4TypeAction) GetActionType() string {
	return ActTypeSetICMP4Type
}

// Currently, we only support Flow.Send() function to generate
// ICMP match/set flow message. We can also support Flow.Next()
// function to generate ICMP match/set flow message in future once
// libOpenflow support NewICMPXxxxField API.
type SetICMPv4CodeAction struct {
	Code uint8
}

func (a *SetICMPv4CodeAction) GetActionMessage() openflow13.Action {
	field, _ := openflow13.FindFieldHeaderByName("NXM_OF_ICMP_CODE", false)
	field.Value = &openflow13.IcmpCodeField{Code: a.Code}
	return openflow13.NewActionSetField(*field)
}

func (a *SetICMPv4CodeAction) GetActionType() string {
	return ActTypeSetICMP4Code
}
