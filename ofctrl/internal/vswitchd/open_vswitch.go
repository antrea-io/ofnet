package vswitchd

// OpenvSwitch defines an object in Open_vSwitch table
// We only include the fields we need
type OpenvSwitch struct {
	UUID    string   `ovsdb:"_uuid"`
	Bridges []string `ovsdb:"bridges"`
}
