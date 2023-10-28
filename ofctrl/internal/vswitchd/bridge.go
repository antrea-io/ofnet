package vswitchd

type (
	BridgeFailMode  = string
	BridgeProtocols = string
)

var (
	BridgeFailModeStandalone  BridgeFailMode  = "standalone"
	BridgeFailModeSecure      BridgeFailMode  = "secure"
	BridgeProtocolsOpenflow10 BridgeProtocols = "OpenFlow10"
	BridgeProtocolsOpenflow11 BridgeProtocols = "OpenFlow11"
	BridgeProtocolsOpenflow12 BridgeProtocols = "OpenFlow12"
	BridgeProtocolsOpenflow13 BridgeProtocols = "OpenFlow13"
	BridgeProtocolsOpenflow14 BridgeProtocols = "OpenFlow14"
	BridgeProtocolsOpenflow15 BridgeProtocols = "OpenFlow15"
)

// Bridge defines an object in Bridge table
// We only include the fields we need
type Bridge struct {
	UUID string `ovsdb:"_uuid"`
	// Include these fields (DatapathID, DatapathVersion) so that libovsdb
	// does not complain about missing model fields.
	DatapathID      *string           `ovsdb:"datapath_id"`
	DatapathType    string            `ovsdb:"datapath_type"`
	DatapathVersion string            `ovsdb:"datapath_version"`
	FailMode        *BridgeFailMode   `ovsdb:"fail_mode"`
	Name            string            `ovsdb:"name"`
	Protocols       []BridgeProtocols `ovsdb:"protocols"`
}
