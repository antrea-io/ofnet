package ofctrl

import (
	"fmt"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/util"
)

type OFError struct {
	Type     uint8
	Code     uint8
	VendorID uint32
	Message  string
}

const (
	OF   = uint32(0)
	OFEx = uint32(0x4f4e4600)

	experimenterErrorType = 0xffff
)

var errMaps = map[uint32]map[uint16]map[uint16]string{
	OF: {
		0: {
			0: "OFPHFC_INCOMPATIBLE",
			1: "OFPHFC_EPERM",
		},
		1: {
			0:  "OFPBRC_BAD_VERSION",
			1:  "OFPBRC_BAD_TYPE",
			2:  "OFPBRC_BAD_STAT",
			3:  "OFPBRC_BAD_VENDOR",
			4:  "OFPBRC_BAD_SUBTYPE",
			5:  "OFPBRC_EPERM",
			6:  "OFPBRC_BAD_LEN",
			7:  "OFPBRC_BUFFER_EMPTY",
			8:  "OFPBRC_BUFFER_UNKNOWN",
			9:  "OFPBRC_BAD_TABLE_ID",
			10: "OFPBRC_IS_SLAVE",
			11: "OFPBRC_BAD_PORT",
			12: "OFPBRC_BAD_PACKET",
			13: "OFPBRC_MULTIPART_BUFFER_OVERFLOW",
		},
		2: {
			0:  "OFPBAC_BAD_TYPE",
			1:  "OFPBAC_BAD_LEN",
			2:  "OFPBAC_BAD_VENDOR",
			3:  "OFPBAC_BAD_VENDOR_TYPE",
			4:  "OFPBAC_BAD_OUT_PORT",
			5:  "OFPBAC_BAD_ARGUMENT",
			6:  "OFPBAC_EPERM",
			7:  "OFPBAC_TOO_MANY",
			8:  "OFPBAC_BAD_QUEUE",
			9:  "OFPBAC_BAD_OUT_GROUP",
			10: "OFPBAC_MATCH_INCONSISTENT",
			11: "OFPBAC_UNSUPPORTED_ORDER",
			12: "OFPBAC_BAD_TAG",
			13: "OFPBAC_BAD_SET_TYPE",
			14: "OFPBAC_BAD_SET_LEN",
			15: "OFPBAC_BAD_SET_ARGUMENT",
		},
		3: {
			0: "OFPBIC_UNKNOWN_INST",
			1: "OFPBIC_UNSUP_INST",
			2: "OFPBIC_BAD_TABLE_ID",
			3: "OFPBIC_UNSUP_METADATA",
			4: "OFPBIC_UNSUP_METADATA_MASK",
			5: "OFPBIC_BAD_EXPERIMENTER",
			6: "OFPBIC_BAD_EXP_TYPE",
			7: "OFPBIC_BAD_LEN",
			8: "OFPBIC_EPERM",
		},
		4: {
			0:  "OFPBMC_BAD_TYPE",
			1:  "OFPBMC_BAD_LEN",
			2:  "OFPBMC_BAD_TAG",
			3:  "OFPBMC_BAD_DL_ADDR_MASK",
			4:  "OFPBMC_BAD_NW_ADDR_MASK",
			5:  "OFPBMC_BAD_WILDCARDS",
			6:  "OFPBMC_BAD_FIELD",
			7:  "OFPBMC_BAD_VALUE",
			8:  "OFPBMC_BAD_MASK",
			9:  "OFPBMC_BAD_PREREQ",
			10: "OFPBMC_DUP_FIELD",
			11: "OFPBMC_EPERM",
		},
		5: {
			0: "OFPFMFC_UNKNOWN",
			1: "OFPFMFC_TABLE_FULL",
			2: "OFPFMFC_BAD_TABLE_ID",
			3: "OFPFMFC_OVERLAP",
			4: "OFPFMFC_EPERM",
			5: "OFPFMFC_BAD_TIMEOUT",
			6: "OFPFMFC_BAD_COMMAND",
			7: "OFPFMFC_BAD_FLAGS",
		},
		6: {
			0:  "OFPGMFC_GROUP_EXISTS",
			1:  "OFPGMFC_INVALID_GROUP",
			2:  "OFPGMFC_WEIGHT_UNSUPPORTED",
			3:  "OFPGMFC_OUT_OF_GROUPS",
			4:  "OFPGMFC_OUT_OF_BUCKETS",
			5:  "OFPGMFC_CHAINING_UNSUPPORTED",
			6:  "OFPGMFC_WATCH_UNSUPPORTED",
			7:  "OFPGMFC_LOOP",
			8:  "OFPGMFC_UNKNOWN_GROUP",
			9:  "OFPGMFC_CHAINED_GROUP",
			10: "OFPGMFC_BAD_TYPE",
			11: "OFPGMFC_BAD_COMMAND",
			12: "OFPGMFC_BAD_BUCKET",
			13: "OFPGMFC_BAD_WATCH",
			14: "OFPGMFC_EPERM",
		},
		7: {
			0: "OFPPMFC_BAD_PORT",
			1: "OFPPMFC_BAD_HW_ADDR",
			2: "OFPPMFC_BAD_CONFIG",
			3: "OFPPMFC_BAD_ADVERTISE",
			4: "OFPPMFC_EPERM",
		},
		8: {
			0: "OFPTMFC_BAD_TABLE",
			1: "OFPTMFC_BAD_CONFIG",
			2: "OFPTMFC_EPERM",
		},
		9: {
			0: "OFPQOFC_BAD_PORT",
			1: "OFPQOFC_BAD_QUEUE",
			2: "OFPQOFC_EPERM",
		},
		10: {
			0: "OFPSCFC_BAD_FLAGS",
			1: "OFPSCFC_BAD_LEN",
			2: "OFPSCFC_EPERM",
		},
		11: {
			0: "OFPRRFC_STALE",
			1: "OFPRRFC_UNSUP",
			2: "OFPRRFC_BAD_ROLE",
		},
		12: {
			0:  "OFPMMFC_UNKNOWN",
			1:  "OFPMMFC_METER_EXISTS",
			2:  "OFPMMFC_INVALID_METER",
			3:  "OFPMMFC_UNKNOWN_METER",
			4:  "OFPMMFC_BAD_COMMAND",
			5:  "OFPMMFC_BAD_FLAGS",
			6:  "OFPMMFC_BAD_RATE",
			7:  "OFPMMFC_BAD_BURST",
			8:  "OFPMMFC_BAD_BAND",
			9:  "OFPMMFC_BAD_BAND_VALUE",
			10: "OFPMMFC_OUT_OF_METERS",
			11: "OFPMMFC_OUT_OF_BANDS",
		},
		13: {
			0: "OFPTFFC_BAD_TABLE",
			1: "OFPTFFC_BAD_METADATA",
			2: "OFPBPC_BAD_TYPE",
			3: "OFPBPC_BAD_LEN",
			4: "OFPBPC_BAD_VALUE",
			5: "OFPTFFC_EPERM",
		},
		16: {
			0: "OFPMOFC_UNKNOWN",
		},
	},
	OFEx: {
		experimenterErrorType: {
			2300: "OFPBFC_UNKNOWN",
			2301: "OFPBFC_EPERM",
			2302: "OFPBFC_BAD_ID",
			2303: "OFPBFC_BUNDLE_EXIST",
			2304: "OFPBFC_BUNDLE_CLOSED",
			2305: "OFPBFC_OUT_OF_BUNDLES",
			2306: "OFPBFC_BAD_TYPE",
			2307: "OFPBFC_BAD_FLAGS",
			2308: "OFPBFC_MSG_BAD_LEN",
			2309: "OFPBFC_MSG_BAD_XID",
			2310: "OFPBFC_MSG_UNSUP",
			2311: "OFPBFC_MSG_CONFLICT",
			2312: "OFPBFC_MSG_TOO_MANY",
			2313: "OFPBFC_MSG_FAILED",
			2314: "OFPBFC_MSG_FAILED",
			2315: "OFPBFC_TIMEOUT",
			2360: "OFPFMFC_BAD_PRIORITY",
			2370: "OFPACFC_INVALID",
			2371: "OFPACFC_UNSUPPORTED",
			2372: "OFPACFC_EPERM",
			2600: "OFPBIC_DUP_INST",
			2640: "OFPBRC_MULTIPART_REQUEST_TIMEOUT",
			2641: "OFPBRC_MULTIPART_REPLY_TIMEOUT",
			4250: "OFPBAC_BAD_SET_MASK",
			4443: "OFPBPC_TOO_MANY",
			4444: "OFPBPC_DUP_TYPE",
			4445: "OFPBPC_BAD_EXPERIMENTER",
			4446: "OFPBPC_BAD_EXP_TYPE",
			4447: "OFPBPC_BAD_EXP_VALUE",
			4448: "OFPBPC_EPERM",

			// NX Extension errors.
			2:  "NXBRC_NXM_INVALID",
			3:  "NXBRC_NXM_BAD_TYPE",
			4:  "NXBRC_MUST_BE_ZERO",
			5:  "NXBRC_BAD_REASON",
			6:  "OFPMOFC_MONITOR_EXISTS",
			7:  "OFPMOFC_BAD_FLAGS",
			8:  "OFPMOFC_UNKNOWN_MONITOR",
			9:  "NXBRC_FM_BAD_EVENT",
			10: "NXBRC_UNENCODABLE_ERROR",
			11: "NXBAC_MUST_BE_ZERO",
			12: "NXFMFC_HARDWARE",
			13: "NXFMFC_BAD_TABLE_ID",
			15: "NXBAC_BAD_CONJUNCTION",
			16: "NXTTMFC_BAD_COMMAND",
			17: "NXTTMFC_BAD_OPT_LEN",
			18: "NXTTMFC_BAD_FIELD_IDX",
			19: "NXTTMFC_TABLE_FULL",
			20: "NXTTMFC_ALREADY_MAPPED",
			21: "NXTTMFC_DUP_ENTRY",
			34: "NXR_NOT_SUPPORTED",
			35: "NXR_STALE",
			36: "NXST_NOT_CONFIGURED",
			37: "NXFMFC_INVALID_TLV_FIELD",
			38: "NXTTMFC_INVALID_TLV_DEL",
			39: "NXBAC_BAD_HEADER_TYPE",
			40: "NXBAC_UNKNOWN_ED_PROP",
			41: "NXBAC_BAD_ED_PROP",
			42: "NXBAC_CT_DATAPATH_SUPPORT",
			43: "NXBMC_CT_DATAPATH_SUPPORT",
			44: "NXTFFC_DUP_TABLE",
		},
	},
}

func GetErrorMessage(errType, errCode uint16, vendor uint32) string {
	unknownError := fmt.Sprintf("unknown error with type %d, code %d, vendor %d", errType, errCode, vendor)
	var vendorErrs map[uint16]map[uint16]string
	if vendor == 0 {
		vendorErrs = errMaps[OF]
	} else {
		vendorErrs = errMaps[OFEx]
	}

	typedErrs, typeFound := vendorErrs[errType]
	if !typeFound {
		return unknownError
	}
	errMsg, codeFound := typedErrs[errCode]
	if !codeFound {
		return unknownError
	}
	return errMsg
}

func GetErrorMessageType(errData util.Buffer) string {
	msgType := errData.Bytes()[1]
	switch msgType {
	case openflow13.Type_Hello:
		return "OFPT_HELLO"
	case openflow13.Type_Error:
		return "OFPT_ERROR"
	case openflow13.Type_EchoRequest:
		return "OFPT_ECHO_REQUEST"
	case openflow13.Type_EchoReply:
		return "OFPT_ECHO_REPLY"
	case openflow13.Type_Experimenter:
		return "OFPT_EXPERIMENTER"
	case openflow13.Type_FeaturesRequest:
		return "OFPT_FEATURES_REQUEST"
	case openflow13.Type_FeaturesReply:
		return "OFPT_FEATURES_REPLY"
	case openflow13.Type_GetConfigRequest:
		return "OFPT_GET_CONFIG_REQUEST"
	case openflow13.Type_GetConfigReply:
		return "OFPT_GET_CONFIG_REPLY"
	case openflow13.Type_SetConfig:
		return "OFPT_SET_CONFIG"
	case openflow13.Type_PacketIn:
		return "OFPT_PACKET_IN"
	case openflow13.Type_FlowRemoved:
		return "OFPT_FLOW_REMOVED"
	case openflow13.Type_PortStatus:
		return "OFPT_PORT_STATUS"
	case openflow13.Type_PacketOut:
		return "OFPT_PACKET_OUT"
	case openflow13.Type_FlowMod:
		return "OFPT_FLOW_MOD"
	case openflow13.Type_GroupMod:
		return "OFPT_GROUP_MOD"
	case openflow13.Type_PortMod:
		return "OFPT_PORT_MOD"
	case openflow13.Type_TableMod:
		return "OFPT_TABLE_MOD"
	case openflow13.Type_BarrierRequest:
		return "OFPT_BARRIER_REQUEST"
	case openflow13.Type_BarrierReply:
		return "OFPT_BARRIER_REPLY"
	case openflow13.Type_QueueGetConfigRequest:
		return "OFPT_QUEUE_GET_CONFIG_REQUEST"
	case openflow13.Type_QueueGetConfigReply:
		return "OFPT_QUEUE_GET_CONFIG_REPLY"
	case openflow13.Type_MultiPartRequest:
		return "OFPT_MULTIPART_REQUEST"
	case openflow13.Type_MultiPartReply:
		return "OFPT_MULTIPART_REPLY"
	default:
		return "Unknown message type"
	}
}
