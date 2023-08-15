package ofctrl

import (
	"errors"
	"fmt"
	"net"

	"antrea.io/libOpenflow/openflow15"
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
	ActTypeMetatdata      = "setMetadata"
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
	ActTypeSetField       = "setField"
	ActTypeCopyField      = "copyField"
	ActTypeMeter          = "meter"
)

type OFAction interface {
	GetActionMessage() openflow15.Action
	GetActionType() string
}

type PushVLANAction struct {
	EtherType uint16
}

func (a *PushVLANAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionPushVlan(a.EtherType)
}

func (a *PushVLANAction) GetActionType() string {
	return ActTypePushVlan
}

type SetVLANAction struct {
	VlanID uint16
}

func (a *SetVLANAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewVlanIdField(a.VlanID, nil)
	return openflow15.NewActionSetField(*field)
}

func (a *SetVLANAction) GetActionType() string {
	return ActTypeSetVlan
}

type PopMPLSAction struct {
	EtherType uint16
}

func (a *PopMPLSAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionPopMpls(a.EtherType)
}

func (a *PopMPLSAction) GetActionType() string {
	return ActTypePopMpls
}

type PushMPLSAction struct {
	EtherType uint16
}

func (a *PushMPLSAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionPushMpls(a.EtherType)
}

func (a *PushMPLSAction) GetActionType() string {
	return ActTypePushMpls
}

type PopVLANAction struct {
}

func (a *PopVLANAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionPopVlan()
}

func (a *PopVLANAction) GetActionType() string {
	return ActTypePopVlan
}

type SetSrcMACAction struct {
	MAC net.HardwareAddr
}

func (a *SetSrcMACAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewEthSrcField(a.MAC, nil)
	return openflow15.NewActionSetField(*field)
}

func (a *SetSrcMACAction) GetActionType() string {
	return ActTypeSetSrcMac
}

type SetDstMACAction struct {
	MAC net.HardwareAddr
}

func (a *SetDstMACAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewEthDstField(a.MAC, nil)
	return openflow15.NewActionSetField(*field)
}

func (a *SetDstMACAction) GetActionType() string {
	return ActTypeSetDstMac
}

type SetTunnelIDAction struct {
	TunnelID uint64
}

func (a *SetTunnelIDAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewTunnelIdField(a.TunnelID)
	return openflow15.NewActionSetField(*field)
}

func (a *SetTunnelIDAction) GetActionType() string {
	return ActTypeSetTunnelID
}

type SetTunnelDstAction struct {
	IP net.IP
}

func (a *SetTunnelDstAction) GetActionMessage() openflow15.Action {
	var field *openflow15.MatchField
	if a.IP.To4() == nil {
		field = NewTunnelIpv6DstField(a.IP, nil)
	} else {
		field = openflow15.NewTunnelIpv4DstField(a.IP, nil)
	}
	return openflow15.NewActionSetField(*field)
}

func NewTunnelIpv6DstField(tunnelIpDst net.IP, tunnelIpDstMask *net.IP) *openflow15.MatchField {
	f := new(openflow15.MatchField)
	f.Class = openflow15.OXM_CLASS_NXM_1
	f.Field = openflow15.NXM_NX_TUN_IPV6_DST
	f.HasMask = false

	ipDstField := new(openflow15.Ipv6DstField)
	ipDstField.Ipv6Dst = tunnelIpDst
	f.Value = ipDstField
	f.Length = uint8(ipDstField.Len())

	// Add the mask
	if tunnelIpDstMask != nil {
		mask := new(openflow15.Ipv6DstField)
		mask.Ipv6Dst = *tunnelIpDstMask
		f.Mask = mask
		f.HasMask = true
		f.Length += uint8(mask.Len())
	}
	return f
}

func NewTunnelIpv6SrcField(tunnelIpSrc net.IP, tunnelIpSrcMask *net.IP) *openflow15.MatchField {
	f := new(openflow15.MatchField)
	f.Class = openflow15.OXM_CLASS_NXM_1
	f.Field = openflow15.NXM_NX_TUN_IPV6_SRC
	f.HasMask = false

	ipSrcField := new(openflow15.Ipv6SrcField)
	ipSrcField.Ipv6Src = tunnelIpSrc
	f.Value = ipSrcField
	f.Length = uint8(ipSrcField.Len())

	// Add the mask
	if tunnelIpSrcMask != nil {
		mask := new(openflow15.Ipv6SrcField)
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

func (a *SetTunnelSrcAction) GetActionMessage() openflow15.Action {
	var field *openflow15.MatchField
	if a.IP.To4() == nil {
		field = NewTunnelIpv6SrcField(a.IP, nil)
	} else {
		field = openflow15.NewTunnelIpv4SrcField(a.IP, nil)
	}
	return openflow15.NewActionSetField(*field)
}

func (a *SetTunnelSrcAction) GetActionType() string {
	return ActTypeSetTunnelSrcIP
}

type SetDstIPAction struct {
	IP     net.IP
	IPMask *net.IP
}

func (a *SetDstIPAction) GetActionMessage() openflow15.Action {
	var field *openflow15.MatchField
	if a.IP.To4() == nil {
		field = openflow15.NewIpv6DstField(a.IP, a.IPMask)
	} else {
		field = openflow15.NewIpv4DstField(a.IP, a.IPMask)
	}
	return openflow15.NewActionSetField(*field)
}

func (a *SetDstIPAction) GetActionType() string {
	return ActTypeSetDstIP
}

type SetSrcIPAction struct {
	IP     net.IP
	IPMask *net.IP
}

func (a *SetSrcIPAction) GetActionMessage() openflow15.Action {
	var field *openflow15.MatchField
	if a.IP.To4() == nil {
		field = openflow15.NewIpv6SrcField(a.IP, a.IPMask)
	} else {
		field = openflow15.NewIpv4SrcField(a.IP, a.IPMask)
	}
	return openflow15.NewActionSetField(*field)
}

func (a *SetSrcIPAction) GetActionType() string {
	return ActTypeSetSrcIP
}

type SetDSCPAction struct {
	Value uint8
	Mask  *uint8
}

func (a *SetDSCPAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewIpDscpField(a.Value, a.Mask)
	return openflow15.NewActionSetField(*field)
}

func (a *SetDSCPAction) GetActionType() string {
	return ActTypeSetDSCP
}

type SetARPOpAction struct {
	Value uint16
}

func (a *SetARPOpAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewArpOperField(a.Value)
	return openflow15.NewActionSetField(*field)
}

func (a *SetARPOpAction) GetActionType() string {
	return ActTypeSetARPOper
}

type SetARPShaAction struct {
	MAC net.HardwareAddr
}

func (a *SetARPShaAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewArpShaField(a.MAC)
	return openflow15.NewActionSetField(*field)
}

func (a *SetARPShaAction) GetActionType() string {
	return ActTypeSetARPSHA
}

type SetARPThaAction struct {
	MAC net.HardwareAddr
}

func (a *SetARPThaAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewArpThaField(a.MAC)
	return openflow15.NewActionSetField(*field)
}

func (a *SetARPThaAction) GetActionType() string {
	return ActTypeSetARPTHA
}

type SetARPSpaAction struct {
	IP net.IP
}

func (a *SetARPSpaAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewArpSpaField(a.IP)
	return openflow15.NewActionSetField(*field)
}

func (a *SetARPSpaAction) GetActionType() string {
	return ActTypeSetARPSPA
}

type SetARPTpaAction struct {
	IP net.IP
}

func (a *SetARPTpaAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewArpTpaField(a.IP)
	return openflow15.NewActionSetField(*field)
}

func (a *SetARPTpaAction) GetActionType() string {
	return ActTypeSetARPTPA
}

type SetTCPSrcPortAction struct {
	Port uint16
}

func (a *SetTCPSrcPortAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewTcpSrcField(a.Port)
	return openflow15.NewActionSetField(*field)
}

func (a *SetTCPSrcPortAction) GetActionType() string {
	return ActTypeSetTCPsPort
}

type SetTCPDstPortAction struct {
	Port uint16
}

func (a *SetTCPDstPortAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewTcpDstField(a.Port)
	return openflow15.NewActionSetField(*field)
}

func (a *SetTCPDstPortAction) GetActionType() string {
	return ActTypeSetTCPdPort
}

type SetTCPFlagsAction struct {
	Flags    uint16
	FlagMask *uint16
}

func (a *SetTCPFlagsAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewTcpFlagsField(a.Flags, a.FlagMask)
	return openflow15.NewActionSetField(*field)
}

func (a *SetTCPFlagsAction) GetActionType() string {
	return ActTypeSetTCPFlags
}

type SetUDPSrcPortAction struct {
	Port uint16
}

func (a *SetUDPSrcPortAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewUdpSrcField(a.Port)
	return openflow15.NewActionSetField(*field)
}

func (a *SetUDPSrcPortAction) GetActionType() string {
	return ActTypeSetUDPsPort
}

type SetUDPDstPortAction struct {
	Port uint16
}

func (a *SetUDPDstPortAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewUdpDstField(a.Port)
	return openflow15.NewActionSetField(*field)
}

func (a *SetUDPDstPortAction) GetActionType() string {
	return ActTypeSetUDPdPort
}

type SetSCTPSrcAction struct {
	Port uint16
}

func (a *SetSCTPSrcAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewSctpSrcField(a.Port)
	return openflow15.NewActionSetField(*field)
}

func (a *SetSCTPSrcAction) GetActionType() string {
	return ActTypeSetSCTPsPort
}

type SetSCTPDstAction struct {
	Port uint16
}

func (a *SetSCTPDstAction) GetActionMessage() openflow15.Action {
	field := openflow15.NewSctpSrcField(a.Port)
	return openflow15.NewActionSetField(*field)
}

func (a *SetSCTPDstAction) GetActionType() string {
	return ActTypeSetSCTPdPort
}

type NXLoadAction struct {
	Field *openflow15.MatchField
	Value uint64
	Range *openflow15.NXRange
}

func (a *NXLoadAction) GetActionMessage() openflow15.Action {
	ofsNbits := a.Range.ToOfsBits()
	return openflow15.NewNXActionRegLoad(ofsNbits, a.Field, a.Value)
}

func (a *NXLoadAction) GetActionType() string {
	return ActTypeNXLoad
}

func (a *NXLoadAction) ResetFieldLength(ofSwitch *OFSwitch) {
	ResetFieldLength(a.Field, ofSwitch.tlvMgr.status)
}

func NewNXLoadAction(fieldName string, data uint64, dataRange *openflow15.NXRange) (*NXLoadAction, error) {
	field, err := openflow15.FindFieldHeaderByName(fieldName, true)
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
	SrcField  *openflow15.MatchField
	DstField  *openflow15.MatchField
	SrcStart  uint16
	DstStart  uint16
	MoveNbits uint16
}

func (a *NXMoveAction) GetActionMessage() openflow15.Action {
	return openflow15.NewNXActionRegMove(a.MoveNbits, a.SrcStart, a.DstStart, a.SrcField, a.DstField)
}

func (a *NXMoveAction) GetActionType() string {
	return ActTypeNXMove
}

func (a *NXMoveAction) ResetFieldsLength(ofSwitch *OFSwitch) {
	ResetFieldLength(a.SrcField, ofSwitch.tlvMgr.status)
	ResetFieldLength(a.DstField, ofSwitch.tlvMgr.status)
}

func NewNXMoveAction(srcName string, dstName string, srcRange *openflow15.NXRange, dstRange *openflow15.NXRange) (*NXMoveAction, error) {
	srcNBits := srcRange.GetNbits()
	srcOfs := srcRange.GetOfs()
	srcField, err := openflow15.FindFieldHeaderByName(srcName, false)
	if err != nil {
		return nil, err
	}
	dstNBits := srcRange.GetNbits()
	dstOfs := srcRange.GetOfs()
	dstField, err := openflow15.FindFieldHeaderByName(dstName, false)
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
	zoneSrcField *openflow15.MatchField
	zoneSrcRange *openflow15.NXRange
	actions      []openflow15.Action
}

func (a *NXConnTrackAction) GetActionMessage() openflow15.Action {
	ctAction := openflow15.NewNXActionConnTrack()
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
func NewNXConnTrackAction(commit bool, force bool, table *uint8, zone *uint16, actions ...openflow15.Action) *NXConnTrackAction {
	return &NXConnTrackAction{
		commit:  commit,
		force:   force,
		table:   table,
		zoneImm: zone,
		actions: actions,
	}
}

// This function support immediate number and field or subfield for ct_zone
func NewNXConnTrackActionWithZoneField(commit bool, force bool, table *uint8, zoneImm *uint16, zoneSrcFieldName string, zoneSrcRange *openflow15.NXRange, actions ...openflow15.Action) *NXConnTrackAction {
	var zoneSrc *openflow15.MatchField
	var zoneSrcRng *openflow15.NXRange
	if zoneSrcFieldName != "" {
		zoneSrc, _ = openflow15.FindFieldHeaderByName(zoneSrcFieldName, true)
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

func (a *NXConjunctionAction) GetActionMessage() openflow15.Action {
	return openflow15.NewNXActionConjunction(a.Clause, a.NClause, a.ID)
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

func (a *DecTTLAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionDecNwTtl()
}

func (a *DecTTLAction) GetActionType() string {
	return ActTypeDecTTL
}

type NXNoteAction struct {
	Notes []byte
}

func (a *NXNoteAction) GetActionMessage() openflow15.Action {
	noteAction := openflow15.NewNXActionNote()
	noteAction.Note = a.Notes
	return noteAction
}

func (a *NXNoteAction) GetActionType() string {
	return ActTypeNXNote
}

type NXController struct {
	Version2     bool
	ControllerID uint16
	Reason       uint8
	UserData     []byte
	MeterID      uint32
	Pause        bool
	MaxLen       *uint16
}

func (a *NXController) GetActionMessage() openflow15.Action {
	// By default, do not buffer, i.e., send the full packet to the controller.
	// Note that OVS does not support buffering and always sends the full
	// packet; it will ignore other values of max_len.
	maxLen := uint16(openflow15.OFPCML_NO_BUFFER)
	if a.MaxLen != nil {
		maxLen = *a.MaxLen
	}
	if a.Version2 {
		action := openflow15.NewNXActionController2()
		action.AddControllerID(a.ControllerID)
		action.AddReason(a.Reason)
		action.AddUserdata(a.UserData)
		action.AddMaxLen(maxLen)
		action.AddMeterID(a.MeterID)
		action.AddPause(a.Pause)
		return action
	}
	action := openflow15.NewNXActionController(a.ControllerID)
	action.MaxLen = maxLen
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

func (a *NXLoadXXRegAction) GetActionMessage() openflow15.Action {
	fieldName := fmt.Sprintf("NXM_NX_XXREG%d", a.FieldNumber)
	field, _ := openflow15.FindFieldHeaderByName(fieldName, len(a.Mask) > 0)
	field.Value = &openflow15.ByteArrayField{Data: a.Value, Length: uint8(len(a.Value))}
	if field.HasMask {
		field.Mask = &openflow15.ByteArrayField{Data: a.Mask, Length: uint8(len(a.Mask))}
	}
	return openflow15.NewNXActionRegLoad2(field)
}

func (a *NXLoadXXRegAction) GetActionType() string {
	return ActTypeNXLoad
}

type SetNDTargetAction struct {
	Target net.IP
}

func (a *SetNDTargetAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_NX_ND_TARGET", false)
	field.Value = &openflow15.Ipv6DstField{Ipv6Dst: a.Target}
	return openflow15.NewActionSetField(*field)
}

func (a *SetNDTargetAction) GetActionType() string {
	return ActTypeSetNDTarget
}

type SetNDSLLAction struct {
	MAC net.HardwareAddr
}

func (a *SetNDSLLAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_NX_ND_SLL", false)
	field.Value = &openflow15.EthSrcField{EthSrc: a.MAC}
	return openflow15.NewActionSetField(*field)
}

func (a *SetNDSLLAction) GetActionType() string {
	return ActTypeSetNDSLL
}

type SetNDTLLAction struct {
	MAC net.HardwareAddr
}

func (a *SetNDTLLAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_NX_ND_TLL", false)
	field.Value = &openflow15.EthDstField{EthDst: a.MAC}
	return openflow15.NewActionSetField(*field)
}

func (a *SetNDTLLAction) GetActionType() string {
	return ActTypeSetNDTLL
}

type SetICMPv6TypeAction struct {
	Type uint8
}

func (a *SetICMPv6TypeAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_NX_ICMPV6_Type", false)
	field.Value = &openflow15.IcmpTypeField{Type: a.Type}
	return openflow15.NewActionSetField(*field)
}

func (a *SetICMPv6TypeAction) GetActionType() string {
	return ActTypeSetICMP6Type
}

type SetICMPv6CodeAction struct {
	Code uint8
}

func (a *SetICMPv6CodeAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_NX_ICMPV6_Code", false)
	field.Value = &openflow15.IcmpCodeField{Code: a.Code}
	return openflow15.NewActionSetField(*field)
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

func (a *SetICMPv4TypeAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_OF_ICMP_TYPE", false)
	field.Value = &openflow15.IcmpTypeField{Type: a.Type}
	return openflow15.NewActionSetField(*field)
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

func (a *SetICMPv4CodeAction) GetActionMessage() openflow15.Action {
	field, _ := openflow15.FindFieldHeaderByName("NXM_OF_ICMP_CODE", false)
	field.Value = &openflow15.IcmpCodeField{Code: a.Code}
	return openflow15.NewActionSetField(*field)
}

func (a *SetICMPv4CodeAction) GetActionType() string {
	return ActTypeSetICMP4Code
}

type CopyFieldAction struct {
	SrcOxmId  openflow15.OxmId
	DstOxmId  openflow15.OxmId
	NBits     uint16
	SrcOffset uint16
	DstOffset uint16
}

func (a *CopyFieldAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionCopyField(a.NBits, a.SrcOffset, a.DstOffset, a.SrcOxmId, a.DstOxmId)
}

func (a *CopyFieldAction) GetActionType() string {
	return ActTypeCopyField
}

func (a *CopyFieldAction) ResetSrcFieldLength(ofSwitch *OFSwitch) {
	matchField := openflow15.MatchField{
		Class:   a.SrcOxmId.Class,
		Field:   a.SrcOxmId.Field,
		HasMask: a.SrcOxmId.HasMask,
	}
	ResetFieldLength(&matchField, ofSwitch.tlvMgr.status)
	a.SrcOxmId.Length = matchField.Length
}

func (a *CopyFieldAction) ResetDstFieldLength(ofSwitch *OFSwitch) {
	matchField := openflow15.MatchField{
		Class:   a.DstOxmId.Class,
		Field:   a.DstOxmId.Field,
		HasMask: a.DstOxmId.HasMask,
	}
	ResetFieldLength(&matchField, ofSwitch.tlvMgr.status)
	a.DstOxmId.Length = matchField.Length
}

func (a *CopyFieldAction) ResetFieldsLength(ofSwitch *OFSwitch) {
	a.ResetSrcFieldLength(ofSwitch)
	a.ResetDstFieldLength(ofSwitch)
}

func NewCopyFieldAction(nBits uint16, srcOffset uint16, dstOffset uint16, srcOxmId *openflow15.OxmId, dstOxmId *openflow15.OxmId) *CopyFieldAction {
	return &CopyFieldAction{
		SrcOxmId:  *srcOxmId,
		DstOxmId:  *dstOxmId,
		NBits:     nBits,
		SrcOffset: srcOffset,
		DstOffset: dstOffset,
	}
}

type SetFieldAction struct {
	Field *openflow15.MatchField
}

func (a *SetFieldAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionSetField(*a.Field)
}

func (a *SetFieldAction) GetActionType() string {
	return ActTypeSetField
}

func NewSetFieldAction(field *openflow15.MatchField) *SetFieldAction {
	return &SetFieldAction{
		Field: field,
	}
}

type MeterAction struct {
	MeterId uint32
}

func (a *MeterAction) GetActionMessage() openflow15.Action {
	return openflow15.NewActionMeter(a.MeterId)
}

func (a *MeterAction) GetActionType() string {
	return ActTypeMeter
}

func NewMeterAction(meterId uint32) *MeterAction {
	return &MeterAction{
		MeterId: meterId,
	}
}
