/***
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

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type OfActor struct {
	Switch            *OFSwitch
	isSwitchConnected bool

	inputTable     *Table
	nextTable      *Table
	connectedCount int

	pktInCount     int
	tlvTableStatus *TLVTableStatus
	tlvMapCh       chan struct{}
}

func (o *OfActor) PacketRcvd(sw *OFSwitch, packet *PacketIn) {
	log.Printf("App: Received packet: %+v", packet.Data)
}

func (o *OfActor) SwitchConnected(sw *OFSwitch) {
	log.Printf("App: Switch connected: %v", sw.DPID())

	// Store switch for later use
	o.Switch = sw

	o.isSwitchConnected = true
	o.connectedCount += 1
}

func (o *OfActor) MultipartReply(sw *OFSwitch, rep *openflow15.MultipartReply) {
}

func (o *OfActor) SwitchDisconnected(sw *OFSwitch) {
	log.Printf("App: Switch disconnected: %v", sw.DPID())
	o.isSwitchConnected = false
}

func (o *OfActor) TLVMapReplyRcvd(sw *OFSwitch, tlvTableStatus *TLVTableStatus) {
	log.Printf("App: Receive TLVMapTable reply: %s", tlvTableStatus)
	o.tlvTableStatus = tlvTableStatus
	if o.tlvMapCh != nil {
		close(o.tlvMapCh)
	}
}

// Controller/Application/ovsBr work on clientMode
var ofActor *OfActor
var ctrler *Controller
var ovsDriver *OvsDriver

// Run an ovs-ofctl command
func runOfctlCmd(cmd, brName string) ([]byte, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow15 %s %s", cmd, brName)
	out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		log.Errorf("error running ovs-ofctl %s %s. Error: %v", cmd, brName, err)
		return nil, err
	}

	return out, nil
}

// dump the flows and parse the Output
func ofctlFlowDump(brName string) ([]string, error) {
	flowDump, err := runOfctlCmd("dump-flows", brName)
	if err != nil {
		log.Errorf("Error running dump-flows on %s: %v", brName, err)
		return nil, err
	}

	log.Infof("Flow dump: %s", flowDump)
	flowOutStr := string(flowDump)
	flowDb := strings.Split(flowOutStr, "\n")[1:]

	log.Infof("flowDb: %+v", flowDb)

	var flowList []string
	for _, flow := range flowDb {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append(felem[:1], felem[2:]...)
			felem = append(felem[:2], felem[5:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}

	log.Infof("flowList: %+v", flowList)

	return flowList, nil
}

// Find a flow in flow list and match its action
func ofctlFlowMatch(flowList []string, tableId int, matchStr, actStr string) bool {
	mtStr := fmt.Sprintf("table=%d, %s ", tableId, matchStr)
	aStr := fmt.Sprintf("actions=%s", actStr)
	for _, flowEntry := range flowList {
		log.Debugf("Looking for %s %s in %s", mtStr, aStr, flowEntry)
		if strings.Contains(flowEntry, mtStr) && strings.Contains(flowEntry, aStr) {
			return true
		}
	}

	return false
}

// ofctlDumpFlowMatch dumps flows and finds a match
func ofctlDumpFlowMatch(brName string, tableId int, matchStr, actStr string) bool {
	// dump flows
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		log.Errorf("Error dumping flows: Err %v", err)
		return false
	}

	return ofctlFlowMatch(flowList, tableId, matchStr, actStr)
}

// Test if OVS switch connects successfully
func TestMain(m *testing.M) {
	var err error
	//Create a controller
	ofActor = new(OfActor)
	ctrler = NewController(ofActor)

	// Create ovs bridge and connect clientMode Controller to it
	ovsDriver = NewOvsDriver("ovsbr12")
	//wait for 2sec and see if ovs br created
	log.Infof("wait for 2sec for ovs bridge ovsbr12 to get created..")
	time.Sleep(2 * time.Second)
	go ctrler.Connect("/var/run/openvswitch/ovsbr12.mgmt")

	//wait for 8sec and see if switch connects
	time.Sleep(8 * time.Second)
	if !ofActor.isSwitchConnected {
		log.Fatalf("ovsbr12 switch did not connect within 20sec")
	}

	log.Infof("Switch connected. Creating tables..")

	// Create initial tables
	ofActor.inputTable = ofActor.Switch.DefaultTable()
	if ofActor.inputTable == nil {
		log.Fatalf("Failed to get input Table")
		return
	}

	ofActor.nextTable, err = ofActor.Switch.NewTable(1)
	if err != nil {
		log.Fatalf("Error creating next Table: %v", err)
		return
	}
	log.Infof("Openflow tables created successfully")

	// run the test
	exitCode := m.Run()

	// delete the bridge
	err = ovsDriver.DeleteBridge(ovsDriver.OvsBridgeName)
	if err != nil {
		log.Fatalf("Error deleting the bridge: %v", err)
	}

	os.Exit(exitCode)
}

// test create/delete Table
func TestTableCreateDelete(t *testing.T) {
	var tables [12]*Table

	log.Infof("Creating tables..")
	// create the tables
	for i := 2; i < 12; i++ {
		var err error
		tables[i], err = ofActor.Switch.NewTable(uint8(i))
		assert.NoErrorf(t, err, "Error creating table: %d", i)
	}

	log.Infof("Deleting tables..")

	// delete the tables
	for i := 2; i < 12; i++ {
		err := tables[i].Delete()
		assert.NoErrorf(t, err, "Error deleting table: %d", i)
	}
}

func TestPushMplsFlow(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// push mpls and install it
	inPortFlow.PushMpls(0x8847)
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify push mpls action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,in_port=1", "push_mpls:0x8847,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,in_port=1", "push_mpls:0x8847,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

func TestPopMplsFlow(t *testing.T) {
	mplsFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x8847,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// pop mpls and install it
	mplsFlow.PopMpls(0x0800)
	err = mplsFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify pop mpls action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,mpls", "pop_mpls:0x0800,goto_table:1"), "mpls flow not found in OVS.")

	// delete the flow
	err = mplsFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,mpls", "pop_mpls:0x0800,goto_table:1"), "mpls flow still found in OVS after deleting it.")
}

func TestCreateDeleteFlow(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set vlan and install it
	inPortFlow.SetVlan(1)
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// create an output
	output, err := ofActor.Switch.OutputPort(1)
	assert.NoError(t, err, "Error creating an output port")

	// create mac flow
	macAddr, _ := net.ParseMAC("02:01:01:01:01:01")
	vlanId := uint16(1)
	macFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority: 100,
		VlanId:   &vlanId,
		MacDa:    &macAddr,
	})
	assert.NoError(t, err, "Error creating mac flow")

	// Remove vlan and send out on a port
	macFlow.PopVlan()
	err = macFlow.Next(output)
	assert.Nil(t, err, "Error installing the mac flow")

	// Install ip flow
	ipAddr := net.ParseIP("10.10.10.10")
	ipFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		IpDa:      &ipAddr,
	})
	assert.NoError(t, err, "Error installing ip flow")

	err = ipFlow.Next(output)
	assert.Nil(t, err, "Error installing the ip flow")

	// install tcp Flow
	tcpFlag := uint16(0x2)
	tcpFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority:     100,
		Ethertype:    0x0800,
		IpProto:      6,
		DstPort:      80,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	assert.NoError(t, err, "Error creating tcp flow")
	err = tcpFlow.Next(output)
	assert.Nil(t, err, "Error installing the tcp flow")

	// verify it got installed
	flowList, err := ofctlFlowDump(ovsDriver.OvsBridgeName)
	assert.Nil(t, err, "Error getting flow entry")

	// Match inport flow
	assert.True(t, ofctlFlowMatch(flowList, 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1"), "in_port flow not found in OVS.")

	// match ip flow
	assert.True(t, ofctlFlowMatch(flowList, 1, "priority=100,ip,nw_dst=10.10.10.10",
		"output:1"), "IP flow not found in OVS.")

	// match mac flow
	assert.True(t, ofctlFlowMatch(flowList, 1, "priority=100,dl_vlan=1,dl_dst=02:01:01:01:01:01",
		"pop_vlan,output:1"), "Mac flow not found in OVS.")

	// match tcp flow
	assert.True(t, ofctlFlowMatch(flowList, 1, "priority=100,tcp,tp_dst=80,tcp_flags=+syn",
		"output:1"), "IP flow not found in OVS.")

	// Delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Delete the flow
	err = macFlow.Delete()
	assert.NoError(t, err, "Error deleting the mac flow")

	// Delete the flow
	err = ipFlow.Delete()
	assert.NoError(t, err, "Error deleting the ip flow")

	// Delete the flow
	err = tcpFlow.Delete()
	assert.NoError(t, err, "Error deleting the tcp flow")

	// Make sure they are really gone
	flowList, err = ofctlFlowDump(ovsDriver.OvsBridgeName)
	assert.NoError(t, err, "Error getting flow entry")

	// Match inport flow and see if its still there..
	assert.False(t, ofctlFlowMatch(flowList, 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1"), "in port flow still found in OVS after deleting it.")

	// match ip flow
	assert.False(t, ofctlFlowMatch(flowList, 1, "priority=100,ip,nw_dst=10.10.10.10",
		"output:1"), "IP flow not found in OVS.")

	// match mac flow
	assert.False(t, ofctlFlowMatch(flowList, 1, "priority=100,dl_vlan=1,dl_dst=02:01:01:01:01:01",
		"pop_vlan,output:1"), "Mac flow not found in OVS.")

	// match tcp flow
	assert.False(t, ofctlFlowMatch(flowList, 1, "priority=100,tcp,tp_dst=80,tcp_flags=+syn",
		"output:1"), "IP flow not found in OVS.")
}

// TestSetUnsetDscp verifies dscp set/unset action
func TestSetUnsetDscp(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpDscp:    46,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set vlan and dscp
	inPortFlow.SetDscp(23)
	inPortFlow.SetVlan(1)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify dscp action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,ip,in_port=1,nw_tos=184",
		"set_field:23->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1"), "in port flow not found in OVS.")

	// unset dscp
	inPortFlow.UnsetDscp()

	// verify dscp action is gone
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,ip,in_port=1,nw_tos=184",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1"), "in_port flow still found in OVS after deleting it.")
}

// TestMatchSetMetadata verifies metadata match & set metedata
func TestMatchSetMetadata(t *testing.T) {
	metadata := uint64(0x1100)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Metadata:     &metadata,
		MetadataMask: &metadata,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set Metadata
	inPortFlow.SetMetadata(uint64(0x8800), uint64(0x8800))

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify metadata action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,metadata=0x1100/0x1100,in_port=1",
		"write_metadata:0x8800/0x8800,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,metadata=0x1100/0x1100,in_port=1",
		"write_metadata:0x8800/0x8800,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

// TestMatchSetTunnelId verifies tunnelId match & set
func TestMatchSetTunnelId(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		TunnelId:  10,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set tunnelId
	inPortFlow.SetTunnelId(20)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify metadata action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tun_id=0xa,in_port=1",
		"set_field:0x14->tun_id,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tun_id=0xa,in_port=1",
		"set_field:0x14->tun_id,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

// TestMatchSetIpFields verifies match & set for ip fields
func TestMatchSetIpFields(t *testing.T) {
	ipSa := net.ParseIP("10.1.1.0")
	ipDa := net.ParseIP("10.2.1.0")
	ipAddrMask := net.ParseIP("255.255.255.0")
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpSa:      &ipSa,
		IpSaMask:  &ipAddrMask,
		IpDa:      &ipDa,
		IpDaMask:  &ipAddrMask,
		IpProto:   IP_PROTO_TCP,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set ip src/dst
	inPortFlow.SetIPField(net.ParseIP("20.2.1.1"), "Dst")
	inPortFlow.SetIPField(net.ParseIP("20.1.1.1"), "Src")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify metadata action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tcp,in_port=1,nw_src=10.1.1.0/24,nw_dst=10.2.1.0/24",
		"set_field:20.2.1.1->ip_dst,set_field:20.1.1.1->ip_src,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tcp,in_port=1,nw_src=10.1.1.0/24,nw_dst=10.2.1.0/24",
		"set_field:20.2.1.1->ip_dst,set_field:20.1.1.1->ip_src,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

// TestMatchIpv6Fields verifies match ipv6 fields
func TestMatchIpv6Fields(t *testing.T) {
	ipv6Sa, ipv6Net, _ := net.ParseCIDR("2016:0616::/100")
	ipv6Da, _, _ := net.ParseCIDR("2016:0617::/100")
	ipv6Mask := net.IP(ipv6Net.Mask)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x86DD,
		IpSa:      &ipv6Sa,
		IpSaMask:  &ipv6Mask,
		IpDa:      &ipv6Da,
		IpDaMask:  &ipv6Mask,
		IpProto:   IP_PROTO_TCP,
		IpDscp:    23,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set Metadata
	inPortFlow.SetDscp(46)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify metadata action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tcp6,in_port=1,ipv6_src=2016:616::/100,ipv6_dst=2016:617::/100,nw_tos=92",
		"set_field:46->ip_dscp,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tcp6,in_port=1,ipv6_src=2016:616::/100,ipv6_dst=2016:617::/100,nw_tos=92",
		"set_field:46->ip_dscp,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

// TestMatchSetTcpFields verifies match & set for tcp fields
func TestMatchSetTcpFields(t *testing.T) {
	tcpFlag := uint16(0x12)
	srcPortMask := uint16(0xfff8)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Ethertype:    0x0800,
		IpProto:      IP_PROTO_TCP,
		SrcPort:      0x8000,
		SrcPortMask:  &srcPortMask,
		DstPort:      9000,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set TCP src/dst
	inPortFlow.SetL4Field(5000, "TCPDst")
	inPortFlow.SetL4Field(4000, "TCPSrc")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify metadata action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tcp,in_port=1,tp_src=0x8000/0xfff8,tp_dst=9000,tcp_flags=+syn+ack",
		"set_field:5000->tcp_dst,set_field:4000->tcp_src,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,tcp,in_port=1,tp_src=0x8000/0xfff8,tp_dst=9000,tcp_flags=+syn+ack",
		"set_field:5000->tcp_dst,set_field:4000->tcp_src,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

// TestMatchSetUdpFields verifies match & set for udp fields
func TestMatchSetUdpFields(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpProto:   IP_PROTO_UDP,
		SrcPort:   8000,
		DstPort:   9000,
	})
	assert.NoError(t, err, "Error creating inport flow")

	// Set TCP src/dst
	inPortFlow.SetL4Field(5000, "UDPDst")
	inPortFlow.SetL4Field(4000, "UDPSrc")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	// verify metadata action exists
	assert.True(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,udp,in_port=1,tp_src=8000,tp_dst=9000",
		"set_field:5000->udp_dst,set_field:4000->udp_src,goto_table:1"), "in port flow not found in OVS.")

	// delete the flow
	err = inPortFlow.Delete()
	assert.NoError(t, err, "Error deleting the inPort flow")

	// Make sure they are really gone
	assert.False(t, ofctlDumpFlowMatch(ovsDriver.OvsBridgeName, 0, "priority=100,udp,in_port=1,tp_src=8000,tp_dst=9000",
		"set_field:5000->udp_dst,set_field:4000->udp_src,goto_table:1"), "in port flow still found in OVS after deleting it.")
}

func TestOFSwitch_DumpFlowStats(t *testing.T) {
	ofActor.Switch.EnableMonitor()
	roundID := uint64(1001)
	categoryID := uint64(1) << 16

	tcpFlag := uint16(0x12)
	flow1, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Ethertype:    0x0800,
		IpProto:      IP_PROTO_TCP,
		SrcPort:      8000,
		DstPort:      9000,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	assert.NoError(t, err, "Error creating inport flow")
	flow1.SetL4Field(4000, "TCPSrc")
	f1 := roundID | categoryID | uint64(1)<<24
	flow1.CookieID = f1
	err = flow1.Next(ofActor.nextTable)
	assert.NoError(t, err, "Error installing inport flow")

	flow2, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpProto:   IP_PROTO_UDP,
		SrcPort:   8000,
		DstPort:   9000,
	})
	assert.NoError(t, err, "Error creating inport flow")
	// Set TCP src/dst
	flow2.SetL4Field(4000, "UDPSrc")
	flow2.SetL4Field(5000, "UDPDst")
	f2 := roundID | categoryID | uint64(2)<<24
	flow2.CookieID = f2

	// install it
	err = flow2.Next(ofActor.nextTable)
	assert.Nil(t, err, "installing inport flow")

	cookieID := roundID | categoryID
	cookieMask := uint64(0xffffff)
	stats, err := ofActor.Switch.DumpFlowStats(cookieID, &cookieMask, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, stats, "Failed to dump flows")
	assert.Equalf(t, 2, len(stats), "Flow count in dump result is incorrect, expected: 2, actual: %d", len(stats))
	for _, stat := range stats {
		fid := stat.Cookie
		assert.Truef(t, fid == f1 || fid == f2, "Flow in dump result has incorrect cookieID: %d", fid)
	}
}

func TestMultiRangeOneReg(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	log.Infof("Enable monitor flows on table %d in bridge %s", ofActor.inputTable.TableId, brName)
	ofActor.Switch.EnableMonitor()

	srcMac1, _ := net.ParseMAC("11:11:11:11:11:11")
	srcIP1 := net.ParseIP("192.168.2.10")
	reg01 := &NXRegister{
		ID:    0,
		Data:  uint32(0x1),
		Range: openflow15.NewNXRange(2, 5),
	}
	reg02 := &NXRegister{
		ID:    0,
		Data:  uint32(0xa),
		Range: openflow15.NewNXRange(6, 9),
	}

	flow1 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
			NxRegs:    []*NXRegister{reg01, reg02},
		},
	}
	flow1.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow1, brName, ofActor.inputTable.TableId,
		"priority=100,ip,reg0=0x284/0x3fc,dl_src=11:11:11:11:11:11,nw_src=192.168.2.10",
		"goto_table:1")

	reg11 := &NXRegister{
		ID:    1,
		Data:  uint32(0x1),
		Range: openflow15.NewNXRange(0, 3),
	}
	reg12 := &NXRegister{
		ID:    1,
		Data:  uint32(0xa),
		Range: openflow15.NewNXRange(4, 7),
	}

	flow2 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
			NxRegs:    []*NXRegister{reg11, reg12},
		},
	}
	flow2.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow2, brName, ofActor.inputTable.TableId,
		"priority=100,ip,reg1=0xa1/0xff,dl_src=11:11:11:11:11:11,nw_src=192.168.2.10",
		"goto_table:1")

	reg21 := &NXRegister{
		ID:    2,
		Data:  uint32(0x1),
		Range: openflow15.NewNXRange(2, 5),
	}
	reg22 := &NXRegister{
		ID:    2,
		Data:  uint32(0xa),
		Range: openflow15.NewNXRange(6, 9),
	}
	reg23 := &NXRegister{
		ID:    2,
		Data:  uint32(11),
		Range: openflow15.NewNXRange(10, 13),
	}

	flow3 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
			NxRegs:    []*NXRegister{reg21, reg23, reg22},
		},
	}
	flow3.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow3, brName, ofActor.inputTable.TableId,
		"priority=100,ip,reg2=0x2e84/0x3ffc,dl_src=11:11:11:11:11:11,nw_src=192.168.2.10",
		"goto_table:1")

}

func (o *OfActor) MaxRetry() int {
	return 5
}

func (o *OfActor) RetryInterval() time.Duration {
	return 1 * time.Second
}

func TestReconnectOFSwitch(t *testing.T) {
	app := new(OfActor)
	ctrl := NewController(app)
	brName := "br4reconn"
	ovsBr := prepareControllerAndSwitch(t, app, ctrl, brName)
	defer func() {
		// Wait for flow entries flush
		time.Sleep(1 * time.Second)
		err := ovsBr.DeleteBridge(brName)
		assert.NoErrorf(t, err, "Failed to delete br %s", brName)
		ctrl.Delete()
	}()
	assert.Equal(t, app.connectedCount, 1)
	go func() {
		ovsBr.DeleteBridge(brName)
		select {
		case <-time.After(10 * time.Second):
			ovsBr = NewOvsDriver(brName)
		}
	}()

	ovsBr.DeleteBridge(brName)
	select {
	case <-time.After(15 * time.Second):
		break
	}
	assert.Equal(t, 2, app.connectedCount)
}

func prepareControllerAndSwitch(t *testing.T, app *OfActor, ctrl *Controller, brName string) (ovsBr *OvsDriver) {
	// Create ovs bridge and connect clientMode Controller to it
	ovsBr = NewOvsDriver(brName)
	go ctrl.Connect(fmt.Sprintf("/var/run/openvswitch/%s.mgmt", brName))

	time.Sleep(2 * time.Second)
	setOfTables(t, app, brName)
	return
}

func setOfTables(t *testing.T, ofActor2 *OfActor, brName string) {
	require.Truef(t, ofActor2.isSwitchConnected, "%s switch did not connect within 8s", brName)
	ofActor2.inputTable = ofActor2.Switch.DefaultTable()
	require.NotNil(t, ofActor2.inputTable)
	var err error
	ofActor2.nextTable, err = ofActor2.Switch.NewTable(1)
	require.Nil(t, err, "error creating next table")
}

func TestBundles(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	// Test transaction complete workflow
	tx := ofActor.Switch.NewTransaction(Atomic)
	err := tx.Begin()
	require.NoError(t, err, "Failed to create transaction")
	_, found := ofActor.Switch.txChans[tx.ID]
	assert.Truef(t, found, "Failed to add transaction with ID %d from switch queues", tx.ID)
	flow1 := createFlow(t, "22:11:11:11:11:11", "192.168.2.11")
	flow2 := createFlow(t, "22:11:11:11:11:12", "192.168.2.12")
	for _, f := range []*Flow{flow1, flow2} {
		fm, err := f.GetBundleMessage(openflow15.FC_ADD)
		require.NoError(t, err, "Failed to generate FlowMod from Flow")
		err = tx.AddMessage(fm)
		require.NoError(t, err, "Failed to add flowMod into transaction")
	}
	count, err := tx.Complete()
	require.NoError(t, err, "Failed to complete transaction")
	assert.Equal(t, 2, count)
	assert.True(t, tx.closed)
	err = tx.Commit()
	require.NoError(t, err, "Failed to commit transaction")
	actionStr := "goto_table:1"
	for _, matchStr := range []string{
		"priority=100,ip,dl_src=22:11:11:11:11:11,nw_src=192.168.2.11",
		"priority=100,ip,dl_src=22:11:11:11:11:12,nw_src=192.168.2.12",
	} {
		assert.Truef(t, ofctlDumpFlowMatch(brName, int(ofActor.inputTable.TableId), matchStr, actionStr),
			"ovsDriver: %s, target flow not found on OVS, match: %s, actions: %s", brName, matchStr, actionStr)
	}
	_, found = ofActor.Switch.txChans[tx.ID]
	assert.False(t, found)

	// Test transaction abort workflow
	tx2 := ofActor.Switch.NewTransaction(Atomic)
	err = tx2.Begin()
	require.NoError(t, err, "Failed to create transaction")
	flow3 := createFlow(t, "22:11:11:11:11:13", "192.168.2.13")
	fm3, err := flow3.GetBundleMessage(openflow15.FC_ADD)
	require.NoError(t, err, "Failed to generate FlowMod from Flow")
	err = tx2.AddMessage(fm3)
	require.NoError(t, err, "Failed to add flowMod into transaction")
	count, err = tx2.Complete()
	require.NoError(t, err, "Failed to complete transaction")
	assert.True(t, tx2.closed)
	assert.Equal(t, 1, count)
	err = tx2.Abort()
	require.NoError(t, err, "Failed to abort transaction")
	matchStr := "priority=100,ip,dl_src=22:11:11:11:11:13,nw_src=192.168.2.13"
	assert.Falsef(t, ofctlDumpFlowMatch(brName, int(ofActor.inputTable.TableId), matchStr, actionStr),
		"ovsDriver: %s, target flow not found on OVS, match: %s, actions: %s", brName, matchStr, actionStr)
	_, found = ofActor.Switch.txChans[tx2.ID]
	assert.False(t, found)

	// Test failure in AddMessage
	tx3 := ofActor.Switch.NewTransaction(Atomic)
	err = tx3.Begin()
	require.NoError(t, err, "Failed to create transaction")
	flow4 := createFlow(t, "33:11:11:11:11:14", "192.168.3.14")
	fm4, err := flow4.GetBundleMessage(openflow15.FC_ADD)
	require.NoError(t, err, "Failed to generate FlowMod from Flow")
	message, _ := tx3.createBundleAddMessage(fm4)
	message.Header.Xid = uint32(100001)
	tx3.ofSwitch.Send(message)
	count, err = tx3.Complete()
	require.NoError(t, err, "Failed to find addMesssage errors transaction")
	assert.True(t, tx3.closed)
	assert.Equal(t, 0, count)
}

func TestBundle2(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	// Test transaction complete workflow
	tx := ofActor.Switch.NewTransaction(Ordered)
	err := tx.Begin()
	require.NoError(t, err, "Failed to create transaction")
	_, found := ofActor.Switch.txChans[tx.ID]
	assert.Truef(t, found, "Failed to add transaction with ID %d from switch queues", tx.ID)

	groupId := uint32(2)
	group1 := newGroup(groupId, GroupSelect, ofActor.Switch)

	natAction := openflow15.NewNXActionCTNAT()
	assert.Nil(t, natAction.SetSNAT(), "Failed to set SNAT action")
	assert.Nil(t, natAction.SetRandom(), "Failed to set random action")
	natAction.SetRangeIPv4Min(net.ParseIP("10.0.0.240"))
	ctAction := openflow15.NewNXActionConnTrack()
	ctAction.Commit()
	ctAction.AddAction(natAction)
	bkt := openflow15.NewBucket(50)
	bkt.AddAction(ctAction)
	group1.AddBuckets(bkt)
	groupMod := group1.GetBundleMessage(openflow15.OFPGC_ADD)

	inPort8 := uint32(11)
	flow1, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort8,
	})
	require.NoError(t, err)
	flow1.NextElem = group1
	flowmod, err := flow1.GetBundleMessage(openflow15.FC_ADD)
	require.NoError(t, err)

	for _, mod := range []OpenFlowModMessage{groupMod, flowmod} {
		err = tx.AddMessage(mod)
		require.NoError(t, err, "Failed to add mod message into transaction")
	}

	count, err := tx.Complete()
	require.NoError(t, err, "Failed to complete transaction")
	assert.Equal(t, 2, count)
	assert.True(t, tx.closed)
	err = tx.Commit()
	require.NoError(t, err, "Failed to commit transaction")
	_, found = ofActor.Switch.txChans[tx.ID]
	assert.False(t, found)

	time.Sleep(2 * time.Second)
	verifyGroup(t, brName, group1, "select", "bucket=bucket_id:50,actions=ct(commit,nat(src=10.0.0.240,random))", true)
	matchStr := "priority=100,ip,in_port=11"
	actionStr := "group:2"
	assert.Truef(t, ofctlDumpFlowMatch(brName, int(ofActor.inputTable.TableId), matchStr, actionStr),
		"br: %s, target flow not found on OVS, match: %s, actions: %s", brName, matchStr, actionStr)
}

func createFlow(t *testing.T, mac, ip string) *Flow {
	srcMac1, _ := net.ParseMAC(mac)
	srcIP1 := net.ParseIP(ip)
	flow1, err := ofActor.inputTable.NewFlow(
		FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
		})
	require.Nil(t, err, "Failed to create flow")
	flow1.NextElem = ofActor.nextTable
	return flow1
}

// Test Nicira extensions for match field and actions
func TestNXExtension(t *testing.T) {
	testNXExtensionsWithOFApplication(ofActor, ovsDriver, t)
}

func TestLearn(t *testing.T) {
	testNXExtensionLearn(ofActor, ovsDriver, t)
}

func TestNotes(t *testing.T) {
	testNXExtensionNote(ofActor, ovsDriver, t)
}

func testNewFlowActionAPIsTest1(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	srcMac1, _ := net.ParseMAC("11:11:11:11:11:11")
	srcIP1 := net.ParseIP("192.168.2.10")
	flow1 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
		},
	}
	newSrcMac1, err := net.ParseMAC("11:11:11:22:22:22")
	require.NoError(t, err)
	ethSrcField := openflow15.NewEthSrcField(newSrcMac1, nil)
	setField := NewSetFieldAction(ethSrcField)
	flow1.ApplyActions([]OFAction{setField})
	flow1.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow1, brName, ofActor.inputTable.TableId,
		"priority=100,ip,dl_src=11:11:11:11:11:11,nw_src=192.168.2.10",
		"set_field:11:11:11:22:22:22->eth_src,goto_table:1")
}

func testNewFlowActionAPIsTest2(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	srcMac1, _ := net.ParseMAC("22:22:22:22:22:22")
	srcIP1 := net.ParseIP("192.168.2.10")
	flow1 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
		},
	}

	reg0Field := openflow15.NewRegMatchFieldWithMask(0, 2, 0xffffffff)
	setField := NewSetFieldAction(reg0Field)
	flow1.ApplyActions([]OFAction{setField})

	flow1.Goto(ofActor.nextTable.TableId)

	verifyNewFlowInstallAndDelete(t, flow1, brName, ofActor.inputTable.TableId,
		"priority=100,ip,dl_src=22:22:22:22:22:22,nw_src=192.168.2.10",
		"set_field:0x2->reg0,goto_table:1")
}

func testNewFlowActionAPIsTest3(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: output in_port
	inPort1 := uint32(103)
	flow3 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			InputPort: inPort1,
		},
	}
	flow3.ApplyActions([]OFAction{NewOutputInPort()})
	verifyNewFlowInstallAndDelete(t, flow3, brName, ofActor.inputTable.TableId,
		"priority=100,in_port=103",
		"IN_PORT")

}

func testNewFlowActionAPIsTest4(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	//Test action: output to register
	inPort2 := uint32(104)
	flow4 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			InputPort: inPort2,
		},
	}
	nxRegOutput, _ := NewNXOutput("NXM_NX_REG1", 5, 10)
	flow4.ApplyActions([]OFAction{nxRegOutput})
	verifyNewFlowInstallAndDelete(t, flow4, brName, ofActor.inputTable.TableId,
		"priority=100,in_port=104",
		"output:NXM_NX_REG1[5..10]")
}

func testNewFlowActionAPIsTest5(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: conjunction
	inPort3 := uint32(105)
	flow5 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			InputPort: inPort3,
		},
	}
	conjunction1, err := NewNXConjunctionAction(uint32(100), uint8(2), uint8(5))
	require.NoError(t, err)
	conjunction2, err := NewNXConjunctionAction(uint32(101), uint8(2), uint8(3))
	require.NoError(t, err)
	flow5.ApplyActions([]OFAction{
		conjunction1,
		conjunction2,
	})
	// install it
	err = flow5.Send(openflow15.FC_ADD)
	require.NoError(t, err)
	matchStr := "priority=100,in_port=105"
	actionStr := "conjunction(100,2/5),conjunction(101,2/3)"
	tableID := int(ofActor.inputTable.TableId)
	// verify metadata action exists
	assert.Truef(t, ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr),
		"conjunction flow match: %s, actions: %s not found in OVS", matchStr, actionStr)
	flow5.MonitorRealizeStatus()
	time.Sleep(1 * time.Second)
	log.Info("Flow realize status is ", flow5.IsRealized())
	flow5.ResetApplyActions([]OFAction{conjunction1})
	err = flow5.Send(openflow15.FC_MODIFY)
	require.NoError(t, err)
	actionStr = "conjunction(100,2/5)"
	// verify metadata action exists
	assert.Truef(t, ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr),
		"conjunction flow match: %s, actions: %s not found in OVS", matchStr, actionStr)
	// delete the flow
	err = flow5.Send(openflow15.FC_DELETE_STRICT)
	require.Nil(t, err, "Error deleting the flow")
	// Make sure they are really gone
	assert.Falsef(t, ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr),
		"br: %s, target flow still found in OVS after deleting it", brName)
}

func testNewFlowActionAPIsTest6(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	// Test action: set tun dst addr
	inPort4 := uint32(106)
	flow6 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			InputPort: inPort4,
		},
	}
	tunDstAddr := net.ParseIP("192.168.2.100")
	flow6.ApplyActions([]OFAction{
		&SetTunnelDstAction{tunDstAddr}})
	flow6.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow6, brName, ofActor.inputTable.TableId,
		"priority=100,in_port=106",
		"set_field:192.168.2.100->tun_dst,goto_table:1")
}

func testNewFlowActionAPIsTest7(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: move eth_src->dst_dst, move arp_sha->arp_tha, move arp_spa->arp_tpa,
	// set_field: arp_op=2, eth_src, arp_sha, arp_spa,
	// output:IN_PORT
	inPort5 := uint32(107)
	flow7 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0806,
			InputPort: inPort5,
			ArpOper:   1,
		},
	}

	sMAC, _ := net.ParseMAC("11:11:11:11:11:22")
	sIP := net.ParseIP("192.168.1.100")
	srcOxmId, err := openflow15.FindOxmIdByName("OXM_OF_ETH_SRC", false)
	require.NoError(t, err)
	dstOxmId, err := openflow15.FindOxmIdByName("OXM_OF_ETH_DST", false)
	require.NoError(t, err)
	move1 := NewCopyFieldAction(48, 0, 0, srcOxmId, dstOxmId)
	srcOxmId, err = openflow15.FindOxmIdByName("OXM_OF_ARP_SHA", false)
	require.NoError(t, err)
	dstOxmId, err = openflow15.FindOxmIdByName("OXM_OF_ARP_THA", false)
	require.NoError(t, err)
	move2 := NewCopyFieldAction(48, 0, 0, srcOxmId, dstOxmId)
	srcOxmId, err = openflow15.FindOxmIdByName("OXM_OF_ARP_SPA", false)
	require.NoError(t, err)
	dstOxmId, err = openflow15.FindOxmIdByName("OXM_OF_ARP_TPA", false)
	require.NoError(t, err)
	move3 := NewCopyFieldAction(32, 0, 0, srcOxmId, dstOxmId)
	flow7.ApplyActions([]OFAction{
		move1, move2, move3,
		&SetARPOpAction{2},
		&SetSrcMACAction{sMAC},
		&SetARPShaAction{sMAC},
		&SetARPSpaAction{sIP},
		NewOutputInPort(),
	})

	// TODO:why is ovs converting OXM to NXM in move action?
	verifyNewFlowInstallAndDelete(t, flow7, brName, ofActor.inputTable.TableId,
		"priority=100,arp,in_port=107,arp_op=1",
		"move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:2->arp_op,set_field:11:11:11:11:11:22->eth_src,set_field:11:11:11:11:11:22->arp_sha,set_field:192.168.1.100->arp_spa,IN_PORT")
}

func testNewFlowActionAPIsTest8_1(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: ct(commit, table=1, zone=0xff01,exec(load:0xf009->NXM_NX_CT_MARK[]))
	inPort6 := uint32(108)
	flow8 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			InputPort: inPort6,
		},
	}
	ctTable := uint8(1)
	ctZone := uint16(0xff01)

	var setFieldMask uint32 = 0xffff
	setField := openflow15.NewCTMarkMatchField(0xf009, &setFieldMask)
	ctLoadAction := openflow15.NewActionSetField(*setField)
	conntrack := NewNXConnTrackAction(true, false, &ctTable, &ctZone, ctLoadAction)
	table2 := uint8(2)
	flow8.ApplyActions([]OFAction{
		conntrack,
		NewResubmit(nil, &ofActor.nextTable.TableId),
		NewResubmit(nil, &table2),
	})
	verifyNewFlowInstallAndDelete(t, flow8, brName, ofActor.inputTable.TableId,
		"priority=100,ip,in_port=108",
		"ct(commit,table=1,zone=65281,exec(set_field:0xf009/0xffff->ct_mark)),resubmit(,1),resubmit(,2)")
}

func testNewFlowActionAPIsTest8_2(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: ct(table=1,zone=NXM_NX_REG1[0..15],nat)
	inPort6 := uint32(108)
	flow80 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			InputPort: inPort6,
		},
	}
	ctTable := uint8(1)
	ctZoneFieldName := "NXM_NX_REG1"
	ctZoneFieldRange := openflow15.NewNXRange(0, 15)
	natAction0 := openflow15.NewNXActionCTNAT()
	conntrack2 := NewNXConnTrackActionWithZoneField(false, false, &ctTable, nil, ctZoneFieldName, ctZoneFieldRange, natAction0)
	flow80.ApplyActions([]OFAction{conntrack2})
	flow80.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow80, brName, ofActor.inputTable.TableId,
		"priority=100,ip,in_port=108",
		"ct(table=1,zone=NXM_NX_REG1[0..15],nat),goto_table:1")
}

func testNewFlowActionAPIsTest9(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: dec_ttl
	inPort7 := uint32(109)
	flow9 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			InputPort: inPort7,
		},
	}
	flow9.ApplyActions([]OFAction{&DecTTLAction{}})
	verifyNewFlowInstallAndDelete(t, flow9, brName, ofActor.inputTable.TableId,
		"priority=100,ip,in_port=109",
		"dec_ttl")
}

func testNewFlowActionAPIsTest10(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test action: ct(commit, exec(move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL, load:0xf009->NXM_NX_CT_MARK[]))
	// Test match: ct_state=+new-trk
	ctStates := openflow15.NewCTStates()
	ctStates.SetNew()
	ctStates.UnsetTrk()
	flow10 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			CtStates:  ctStates,
		},
	}
	ctMoveSrc, err := openflow15.FindOxmIdByName("NXM_OF_ETH_SRC", false)
	require.NoError(t, err)
	ctMoveDst, err := openflow15.FindOxmIdByName("NXM_NX_CT_LABEL", false)
	require.NoError(t, err)
	ctMoveAction := openflow15.NewActionCopyField(48, 0, 0, *ctMoveSrc, *ctMoveDst)

	var setFieldMask uint32 = 0xffff
	setField := openflow15.NewCTMarkMatchField(0xf009, &setFieldMask)
	ctLoadAction := openflow15.NewActionSetField(*setField)

	conntrack3 := NewNXConnTrackAction(true, false, nil, nil, ctMoveAction, ctLoadAction)
	flow10.ApplyActions([]OFAction{conntrack3})
	verifyNewFlowInstallAndDelete(t, flow10, brName, ofActor.inputTable.TableId,
		"priority=100,ct_state=+new-trk,ip",
		"ct(commit,exec(move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL[0..47],set_field:0xf009/0xffff->ct_mark))")
}

func testNewFlowActionAPIsTest11(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	//Test match: reg1=0x12/0xffff
	reg1 := &NXRegister{
		ID:    2,
		Data:  uint32(0x12),
		Range: openflow15.NewNXRange(0, 15),
	}
	var regs = []*NXRegister{reg1}
	flow11 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			NxRegs:    regs,
		},
	}
	conntrack4 := NewNXConnTrackAction(true, false, nil, nil)
	flow11.ApplyActions([]OFAction{conntrack4, NewResubmit(nil, &ofActor.nextTable.TableId)})
	verifyNewFlowInstallAndDelete(t, flow11, brName, ofActor.inputTable.TableId,
		"priority=100,ip,reg2=0x12/0xffff",
		"ct(commit),resubmit(,1)")
}

func testNewFlowActionAPIsTest12(t *testing.T) {
	brName := ovsDriver.OvsBridgeName

	// Test group
	groupId := uint32(11)
	group1 := newGroup(groupId, GroupSelect, ofActor.Switch)

	natAction := openflow15.NewNXActionCTNAT()
	assert.Nil(t, natAction.SetSNAT(), "Failed to set SNAT action")
	assert.Nil(t, natAction.SetRandom(), "Failed to set random action")
	natAction.SetRangeIPv4Min(net.ParseIP("10.0.0.240"))
	ctAction := NewNXConnTrackAction(true, false, nil, nil, natAction)
	bkt := openflow15.NewBucket(50)
	bkt.AddAction(ctAction.GetActionMessage())
	group1.AddBuckets(bkt)
	err := group1.Install()
	assert.NoError(t, err, "Failed to install group entry")

	verifyGroup(t, brName, group1, "select", "bucket=bucket_id:50,actions=ct(commit,nat(src=10.0.0.240,random))", true)

	// Install flow and refer to group
	inPort8 := uint32(110)
	flow13 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			InputPort: inPort8,
		},
	}
	flow13.ApplyActions([]OFAction{group1})
	verifyFlowInstallAndDelete(t, flow13, group1, brName, ofActor.inputTable.TableId,
		"priority=100,ip,in_port=110",
		"group:1")
	group1.Delete()
	verifyGroup(t, brName, group1, "select", "bucket=bucket_id:50,actions=ct(commit,nat(src=10.0.0.240,random))", false)
}

func TestNewFlowActionAPIs(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	log.Infof("Enable monitor flows on table %d in bridge %s", ofActor.inputTable.TableId, brName)
	ofActor.Switch.EnableMonitor()

	testNewFlowActionAPIsTest1(t)
	testNewFlowActionAPIsTest2(t)
	testNewFlowActionAPIsTest3(t)
	testNewFlowActionAPIsTest4(t)
	testNewFlowActionAPIsTest5(t)
	testNewFlowActionAPIsTest6(t)
	testNewFlowActionAPIsTest7(t)
	testNewFlowActionAPIsTest8_1(t)
	testNewFlowActionAPIsTest8_2(t)
	testNewFlowActionAPIsTest9(t)
	testNewFlowActionAPIsTest10(t)
	testNewFlowActionAPIsTest11(t)
	testNewFlowActionAPIsTest12(t)
}

func TestSetTunnelMetadata(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	log.Infof("Enable monitor flows on table %d in bridge %s", ofActor.inputTable.TableId, brName)
	ofActor.Switch.EnableMonitor()

	tlvMap := &openflow15.TLVTableMap{OptClass: 0xff01, OptType: 0, OptLength: 4, Index: 0}
	err := ofActor.Switch.AddTunnelTLVMap(tlvMap.OptClass, tlvMap.OptType, tlvMap.OptLength, tlvMap.Index)
	require.NoError(t, err)

	// Test "AddTunnelTLVMap" is idempotent
	err = ofActor.Switch.AddTunnelTLVMap(tlvMap.OptClass, tlvMap.OptType, tlvMap.OptLength, tlvMap.Index)
	require.NoError(t, err)

	inPort9 := uint32(111)
	flow14 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			InputPort: inPort9,
		},
	}
	tunMetadataField := openflow15.NewTunMetadataField(0, []byte{0x00, 0x00, 0x01, 0x02}, []byte{0x00, 0x00, 0xff, 0xff})
	setFieldAction := NewSetFieldAction(tunMetadataField)

	flow14.ApplyActions([]OFAction{setFieldAction})
	verifyNewFlowInstallAndDelete(t, flow14, brName, ofActor.inputTable.TableId,
		"priority=100,ip,in_port=111",
		"set_field:0x102/0xffff->tun_metadata0")

	inPort10 := uint32(112)
	rng15 := openflow15.NewNXRange(8, 23)

	flow15 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  100,
			InputPort: inPort10,
			Ethertype: 0x0800,
			TunMetadatas: []*NXTunMetadata{
				{
					ID:    0,
					Data:  uint32(0x34),
					Range: rng15,
				}},
		},
	}

	srcOxmId, err := openflow15.FindOxmIdByName("NXM_NX_TUN_METADATA0", false)
	require.NoError(t, err)
	dstOxmId, err := openflow15.FindOxmIdByName("NXM_NX_REG0", false)
	require.NoError(t, err)
	moveAction := NewCopyFieldAction(4, 28, 28, srcOxmId, dstOxmId)

	moveAction.ResetSrcFieldLength(ofActor.Switch)
	flow15.ApplyActions([]OFAction{moveAction})
	flow15.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow15, brName, ofActor.inputTable.TableId,
		"priority=100,ip,tun_metadata0=0x3400/0xffff00,in_port=112",
		"move:NXM_NX_TUN_METADATA0[28..31]->NXM_NX_REG0[28..31],goto_table:1")

	err = ofActor.Switch.DeleteTunnelTLVMap([]*openflow15.TLVTableMap{tlvMap})
	require.NoError(t, err)
}

func TestGetMaskBytes(t *testing.T) {
	rngBytes := getMaskBytes(8, 16)
	assert.Equal(t, 4, len(rngBytes))
	maskString := fmt.Sprintf("0x%x", rngBytes)
	assert.Equal(t, "0x00ffff00", maskString)
}

func TestModPort(t *testing.T) {
	app := new(OfActor)
	ctrl := NewController(app)
	brName := "br4modPort"
	ovsBr := prepareControllerAndSwitch(t, app, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()

	testPort := "test"
	portNo := 100
	cmd := fmt.Sprintf("ovs-vsctl --may-exist add-port %s %s -- set Interface %s type=internal ofport_request=%d", brName, testPort, testPort, portNo)
	err := exec.Command("/bin/bash", "-c", cmd).Run()
	require.NoError(t, err)
	time.Sleep(1 * time.Second)

	cmd2 := fmt.Sprintf("ovs-vsctl get Interface %s mac_in_use", testPort)
	macBytes, err := exec.Command("/bin/bash", "-c", cmd2).Output()
	require.NoError(t, err)
	macStr := strings.TrimRight(string(macBytes), "\n")
	macStr = strings.Trim(macStr, "\"")
	mac, _ := net.ParseMAC(macStr)
	err = app.Switch.DisableOFPortForwarding(portNo, mac)
	require.NoError(t, err)
}

func TestCtMatch(t *testing.T) {
	app := new(OfActor)
	ctrl := NewController(app)
	brName := "br4ctMatch"
	ovsBr := prepareControllerAndSwitch(t, app, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()

	app.Switch.EnableMonitor()

	ctStates := openflow15.NewCTStates()
	ctStates.SetNew()
	inPort1 := uint32(201)
	ctIpSrc := net.ParseIP("1.1.1.1")
	flow1 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			InputPort: inPort1,
			CtStates:  ctStates,
			CtIpSa:    &ctIpSrc,
		},
	}
	flow1.Goto(app.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow1, brName, app.inputTable.TableId,
		"priority=100,ct_state=+new,ct_nw_src=1.1.1.1,ip,in_port=201",
		"goto_table:1")

	inPort2 := uint32(202)
	ctIpDst := net.ParseIP("2.2.2.2")
	flow2 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:    100,
			Ethertype:   0x0800,
			InputPort:   inPort2,
			CtStates:    ctStates,
			CtIpDa:      &ctIpDst,
			CtIpProto:   IP_PROTO_TCP,
			CtTpSrcPort: 1001,
			CtTpDstPort: 2002,
		},
	}
	flow2.Goto(app.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow2, brName, app.inputTable.TableId,
		"priority=100,ct_state=+new,ct_nw_dst=2.2.2.2,ct_nw_proto=6,ct_tp_src=1001,ct_tp_dst=2002,ip,in_port=202",
		"goto_table:1")

	ctIpSrc2 := net.ParseIP("3.3.3.0")
	ctIpSrc2Mask := net.ParseIP("255.255.255.0")
	flow3 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:    100,
			Ethertype:   0x0800,
			InputPort:   inPort2,
			CtStates:    ctStates,
			CtIpSa:      &ctIpSrc2,
			CtIpSaMask:  &ctIpSrc2Mask,
			CtIpProto:   IP_PROTO_TCP,
			CtTpSrcPort: 1001,
			CtTpDstPort: 2002,
		},
	}
	flow3.Goto(app.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow3, brName, app.inputTable.TableId,
		"priority=100,ct_state=+new,ct_nw_src=3.3.3.0/24,ct_nw_proto=6,ct_tp_src=1001,ct_tp_dst=2002,ip,in_port=202",
		"goto_table:1")
}

func TestIPv6Flows(t *testing.T) {
	app := new(OfActor)
	ctrl := NewController(app)
	brName := "br4IPv6"
	ovsBr := prepareControllerAndSwitch(t, app, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()

	app.Switch.EnableMonitor()

	inport1 := uint32(1)
	flow1 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x86dd,
			InputPort: inport1,
		},
	}
	sIP, ipNet, _ := net.ParseCIDR("abcd:234::2/32")
	dIP := net.ParseIP("abcd:1234::2")
	sIPMask := net.IP(ipNet.Mask)
	setDIP := &SetDstIPAction{
		IP:     dIP,
		IPMask: nil,
	}
	setSIP := &SetSrcIPAction{
		IP:     sIP,
		IPMask: nil,
	}
	flow1.ApplyActions([]OFAction{setDIP, setSIP})
	flow1.Goto(app.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow1, brName, app.inputTable.TableId,
		"priority=100,ipv6,in_port=1",
		"set_field:abcd:1234::2->ipv6_dst,set_field:abcd:234::2->ipv6_src,goto_table:1")

	flow2 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x86dd,
			IpSa:      &ipNet.IP,
			IpSaMask:  &sIPMask,
			IpDa:      &dIP,
		},
	}
	flow2.Drop()
	verifyNewFlowInstallAndDelete(t, flow2, brName, app.inputTable.TableId,
		"priority=100,ipv6,ipv6_src=abcd:234::/32,ipv6_dst=abcd:1234::2",
		"drop")

	inport3 := uint32(3)
	flow3 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x86dd,
			InputPort: inport3,
		},
	}
	flow3.Goto(app.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow3, brName, app.inputTable.TableId,
		"priority=100,ipv6,in_port=3", "goto_table:1")

	inport4 := uint32(4)
	flow4 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x86dd,
			InputPort: inport4,
			XxRegs: []*XXRegister{
				{
					ID:   3,
					Data: dIP,
				},
			},
		},
	}
	flow4.Drop()
	verifyNewFlowInstallAndDelete(t, flow4, brName, app.inputTable.TableId,
		"priority=100,ipv6,reg12=0xabcd1234,reg13=0,reg14=0,reg15=0x2,in_port=4",
		"drop")

	inport5 := uint32(5)
	icmp6Code := uint8(0)
	icmp6Type := uint8(135)
	flow5 := &Flow{
		Table: app.inputTable,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x86dd,
			InputPort: inport5,
			IpProto:   58,
			Icmp6Type: &icmp6Type,
			Icmp6Code: &icmp6Code,
		},
	}
	tgtIP := net.ParseIP("2001:1:1:1443::ab:1004")
	setNDTargetAct := &SetNDTargetAction{
		Target: tgtIP,
	}
	setICMP6TypeAct := &SetICMPv6TypeAction{Type: 136}
	flow5.ApplyActions([]OFAction{setNDTargetAct, setICMP6TypeAct})
	flow5.Goto(app.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow5, brName, app.inputTable.TableId,
		"priority=100,icmp6,in_port=5,icmp_type=135,icmp_code=0",
		"set_field:2001:1:1:1443::ab:1004->nd_target,set_field:136->icmpv6_type,goto_table:1")
}

func testNXExtensionNote(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	brName := ovsBr.OvsBridgeName
	log.Infof("Enable monitor flows on Table %d in bridge %s", ofApp.inputTable.TableId, brName)
	ofApp.Switch.EnableMonitor()
	srcMac1, _ := net.ParseMAC("33:33:11:11:11:11")
	srcIP1 := net.ParseIP("192.168.1.10")
	notes := []byte("test:abcd efgs.")
	flow1, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac1,
		IpSa:      &srcIP1,
	})
	require.NoError(t, err)
	err = flow1.Note(notes)
	require.NoError(t, err)
	err = flow1.Next(ofApp.nextTable)
	require.NoError(t, err)
}

func testNXExtensionLearn(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	brName := ovsBr.OvsBridgeName
	log.Infof("Enable monitor flows on Table %d in bridge %s", ofApp.inputTable.TableId, brName)
	ofApp.Switch.EnableMonitor()
	srcMac1, _ := net.ParseMAC("22:22:11:11:11:11")
	srcIP1 := net.ParseIP("192.168.1.10")
	flow1, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac1,
		IpSa:      &srcIP1,
	})
	require.NoError(t, err)

	learn := &FlowLearn{
		idleTimeout:    10,
		hardTimeout:    20,
		priority:       80,
		cookie:         0x123456789abcdef0,
		tableID:        2,
		finIdleTimeout: 2,
		finHardTimeout: 4,
	}

	srcValue1 := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue1, 99)
	srcValue4 := make([]byte, 8)
	binary.BigEndian.PutUint64(srcValue4, 0xaaaaaabbbbbb)

	matchField1 := &LearnField{Start: 0, Name: "NXM_OF_IN_PORT"}
	err = learn.AddMatch(matchField1, 16, nil, srcValue1)
	require.NoError(t, err)
	matchField2 := &LearnField{Start: 0, Name: "NXM_OF_ETH_DST"}
	fromField2 := &LearnField{Start: 0, Name: "NXM_OF_ETH_SRC"}
	err = learn.AddMatch(matchField2, 48, fromField2, nil)
	require.NoError(t, err)
	loadField3 := &LearnField{Start: 0, Name: "NXM_NX_REG1"}
	fromField3 := &LearnField{Start: 0, Name: "NXM_OF_IN_PORT"}
	err = learn.AddLoadAction(loadField3, 16, fromField3, nil)
	require.NoError(t, err)
	loadField4 := &LearnField{Start: 0, Name: "NXM_OF_ETH_SRC"}
	err = learn.AddLoadAction(loadField4, 48, nil, srcValue4)
	require.NoError(t, err)
	outputField5 := &LearnField{Start: 0, Name: "NXM_OF_IN_PORT"}
	err = learn.AddOutputAction(outputField5, 16)
	require.NoError(t, err)
	err = flow1.Learn(learn)
	require.NoError(t, err)

	err = flow1.Next(ofApp.nextTable)
	require.NoError(t, err)
	verifyFlowInstallAndDelete(t, flow1, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,dl_src=22:22:11:11:11:11,nw_src=192.168.1.10",
		"learn(table=2,idle_timeout=10,hard_timeout=20,fin_idle_timeout=2,fin_hard_timeout=4,priority=80,cookie=0x123456789abcdef0,in_port=99,NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:NXM_OF_IN_PORT[]->NXM_NX_REG1[0..15],load:0xaaaaaabb->NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),goto_table:1")

}

func testNXExtensionsTest1(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: load mac to src mac
	brName := ovsBr.OvsBridgeName
	srcMac1, _ := net.ParseMAC("11:11:11:11:11:11")
	srcIP1 := net.ParseIP("192.168.1.10")
	flow1, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac1,
		IpSa:      &srcIP1,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow1)

	newSrcMac, err := net.ParseMAC("11:11:11:22:22:22")
	assert.NoErrorf(t, err, "Error creating Src Mac using ParseMAC")
	ethSrcField := openflow15.NewEthSrcField(newSrcMac, nil)
	err = flow1.SetField(ethSrcField)
	assert.NoError(t, err, "Failed to load data into field OXM_OF_ETH_SRC")
	verifyFlowInstallAndDelete(t, flow1, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,dl_src=11:11:11:11:11:11,nw_src=192.168.1.10",
		"set_field:11:11:11:22:22:22->eth_src,goto_table:1")
}

func testNXExtensionsTest2_1(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: move src mac to dst mac
	brName := ovsBr.OvsBridgeName
	srcIP1 := net.ParseIP("192.168.1.10")
	srcMac2, _ := net.ParseMAC("11:11:11:11:11:22")
	flow2, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac2,
		IpSa:      &srcIP1,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow2)
	ethSrcOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ETH_SRC, false, 6, 0)
	ethDstOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ETH_DST, false, 6, 0)
	err = flow2.CopyField(48, 0, 0, ethSrcOxmId, ethDstOxmId)
	assert.NoError(t, err, "Failed to move data from OXM_FIELD_ETH_SRC to OXM_FIELD_ETH_DST")
	verifyFlowInstallAndDelete(t, flow2, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,dl_src=11:11:11:11:11:22,nw_src=192.168.1.10",
		"move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],goto_table:1")
}

func testNXExtensionsTest2_2(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: move src reg to dst reg, testing NXM match field
	//              support in CopyField action.
	brName := ovsBr.OvsBridgeName
	srcIP1 := net.ParseIP("192.168.1.10")
	srcMac2, _ := net.ParseMAC("11:11:11:11:11:22")
	flow2, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac2,
		IpSa:      &srcIP1,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow2)
	reg5OxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_NXM_1,
		openflow15.NXM_NX_REG5, false, 4, 0)
	reg6OxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_NXM_1,
		openflow15.NXM_NX_REG6, false, 4, 0)
	err = flow2.CopyField(32, 0, 0, reg5OxmId, reg6OxmId)
	assert.NoError(t, err, "Failed to move data from NXM_NX_REG5 to NXM_NX_REG6")
	verifyFlowInstallAndDelete(t, flow2, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,dl_src=11:11:11:11:11:22,nw_src=192.168.1.10",
		"move:NXM_NX_REG5[]->NXM_NX_REG6[],goto_table:1")
}

func testNXExtensionsTest3(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: output in_port
	brName := ovsBr.OvsBridgeName
	inPort1 := uint32(3)
	flow3, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort1,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow3)
	verifyFlowInstallAndDelete(t, flow3, NewOutputInPort(), brName, ofApp.inputTable.TableId,
		"priority=100,in_port=3",
		"IN_PORT")
}

func testNXExtensionsTest4(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	//Test action: output to register
	brName := ovsBr.OvsBridgeName
	inPort2 := uint32(4)
	flow4, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort2,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow4)
	flow4.OutputReg("NXM_NX_REG1", 5, 10)
	verifyFlowInstallAndDelete(t, flow4, NewEmptyElem(), brName, ofApp.inputTable.TableId,
		"priority=100,in_port=4",
		"output:NXM_NX_REG1[5..10]")
}

func testNXExtensionsTest5(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: conjunction
	brName := ovsBr.OvsBridgeName
	inPort3 := uint32(5)
	flow5, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort3,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow5)

	_ = flow5.AddConjunction(uint32(100), uint8(2), uint8(5))
	_ = flow5.AddConjunction(uint32(101), uint8(2), uint8(3))
	// install it
	err = flow5.Next(NewEmptyElem())
	assert.NoError(t, err, "Error installing inport flow")
	matchStr := "priority=100,in_port=5"
	actionStr := "conjunction(100,2/5),conjunction(101,2/3)"
	tableID := int(ofApp.inputTable.TableId)
	// verify metadata action exists
	assert.Truef(t, ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr),
		"conjunction flow match: %s, actions: %s not found in OVS", matchStr, actionStr)
	flow5.MonitorRealizeStatus()
	time.Sleep(1 * time.Second)
	log.Info("Flow realize status is ", flow5.IsRealized())

	_ = flow5.DelConjunction(uint32(101))
	actionStr = "conjunction(100,2/5)"
	// verify metadata action exists
	assert.Truef(t, ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr),
		"conjunction flow match: %s, actions: %s not found in OVS", matchStr, actionStr)

	err = flow5.DelConjunction(uint32(100))
	assert.Equal(t, EmptyFlowActionError, err, "Failed to find no action left in flow actions")

	// delete the flow
	err = flow5.Delete()
	assert.NoError(t, err, "Error deleting the flow")

	// Make sure they are really gone
	assert.Falsef(t, ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr),
		"br: %s, target flow still found in OVS after deleting it", brName)
}

func testNXExtensionsTest6(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: set tun dst addr
	brName := ovsBr.OvsBridgeName
	inPort4 := uint32(6)
	flow6, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort4,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow6)
	tunDstAddr := net.ParseIP("192.168.1.100")
	err = flow6.SetIPField(tunDstAddr, "TunDst")
	require.NoError(t, err)
	verifyFlowInstallAndDelete(t, flow6, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,in_port=6",
		"set_field:192.168.1.100->tun_dst,goto_table:1")
}

func testNXExtensionsTest7(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: move eth_src->dst_dst, move arp_sha->arp_tha, move arp_spa->arp_tpa,
	// set_field: arp_op=2, eth_src, arp_sha, arp_spa,
	// output:IN_PORT
	brName := ovsBr.OvsBridgeName
	inPort5 := uint32(7)
	flow7, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0806,
		InputPort: inPort5,
		ArpOper:   1,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow7)
	sMAC, _ := net.ParseMAC("11:11:11:11:11:22")
	sIP := net.ParseIP("192.168.1.100")

	ethSrcOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ETH_SRC, false, 6, 0)
	ethDstOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ETH_DST, false, 6, 0)
	err = flow7.CopyField(48, 0, 0, ethSrcOxmId, ethDstOxmId)
	assert.NoError(t, err, "Failed to move data from NXM_OF_ETH_SRC to NXM_OF_ETH_DST")

	arpShaOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ARP_SHA, false, 6, 0)
	arpThaOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ARP_THA, false, 6, 0)
	err = flow7.CopyField(48, 0, 0, arpShaOxmId, arpThaOxmId)
	assert.NoError(t, err, "Failed to move data from NXM_NX_ARP_SHA to NXM_NX_ARP_THA")

	arpSpaOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ARP_SPA, false, 4, 0)
	arpTpaOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ARP_TPA, false, 4, 0)
	err = flow7.CopyField(32, 0, 0, arpSpaOxmId, arpTpaOxmId)
	assert.NoError(t, err, "Failed to move data from NXM_OF_ARP_SPA to NXM_OF_ARP_TPA")

	_ = flow7.SetARPOper(2)
	_ = flow7.SetMacSa(sMAC)
	_ = flow7.SetARPSha(sMAC)
	_ = flow7.SetARPSpa(sIP)
	verifyFlowInstallAndDelete(t, flow7, NewOutputInPort(), brName, ofApp.inputTable.TableId,
		"priority=100,arp,in_port=7,arp_op=1",
		"move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:2->arp_op,set_field:11:11:11:11:11:22->eth_src,set_field:11:11:11:11:11:22->arp_sha,set_field:192.168.1.100->arp_spa,IN_PORT")
}

func testNXExtensionsTest8(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: ct(commit, table=1, zone=0xff01,exec(load:0xf009->NXM_NX_CT_MARK[]))
	brName := ovsBr.OvsBridgeName
	inPort6 := uint32(8)
	flow8, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort6,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow8)
	ctTable := uint8(1)
	ctZone := uint16(0xff01)
	var setFieldMask uint32 = 0xffff
	setField := openflow15.NewCTMarkMatchField(0xf009, &setFieldMask)
	ctLoadAction := openflow15.NewActionSetField(*setField)
	err = flow8.ConnTrack(true, false, &ctTable, &ctZone, ctLoadAction)
	assert.NoError(t, err, "Failed to apply ct action")
	verifyFlowInstallAndDelete(t, flow8, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=8",
		"ct(commit,table=1,zone=65281,exec(set_field:0xf009/0xffff->ct_mark)),goto_table:1")

	// Test action: ct(table=1,zone=0xff01,nat)
	flow80, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort6,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow80)
	natAction0 := openflow15.NewNXActionCTNAT()
	err = flow80.ConnTrack(false, false, &ctTable, &ctZone, natAction0)
	assert.NoError(t, err, "Failed to apply ct action")
	verifyFlowInstallAndDelete(t, flow80, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=8",
		"ct(table=1,zone=65281,nat),goto_table:1")
}

func testNXExtensionsTest9(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: dec_ttl
	brName := ovsBr.OvsBridgeName
	inPort7 := uint32(9)
	flow9, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort7,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow9)
	err = flow9.DecTTL()
	assert.NoError(t, err, "Failed to apply dec_ttl action")
	verifyFlowInstallAndDelete(t, flow9, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=9",
		"dec_ttl,goto_table:1")
}

func testNXExtensionsTest10(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test action: ct(commit, exec(move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL, load:0xf009->NXM_NX_CT_MARK[]))
	// Test match: ct_state=+new-trk
	brName := ovsBr.OvsBridgeName
	ctStates := openflow15.NewCTStates()
	ctStates.SetNew()
	ctStates.UnsetTrk()
	flow10, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		CtStates:  ctStates,
	})
	require.Nilf(t, err, "Failed to generate flow: %+v", flow10)

	var setFieldMask uint32 = 0xffff
	setField := openflow15.NewCTMarkMatchField(0xf009, &setFieldMask)
	ctLoadAction := openflow15.NewActionSetField(*setField)

	ethSrcOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_OPENFLOW_BASIC,
		openflow15.OXM_FIELD_ETH_SRC, false, 6, 0)
	ctLableOxmId := openflow15.NewOxmId(openflow15.OXM_CLASS_NXM_1,
		openflow15.NXM_NX_CT_LABEL, false, 16, 0)
	ctMoveAction := openflow15.NewActionCopyField(48, 0, 0, *ethSrcOxmId, *ctLableOxmId)

	err = flow10.ConnTrack(true, false, nil, nil, ctMoveAction, ctLoadAction)
	assert.NoError(t, err, "Failed to apply dec_ttl action")
	verifyFlowInstallAndDelete(t, flow10, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ct_state=+new-trk,ip",
		"ct(commit,exec(move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL[0..47],set_field:0xf009/0xffff->ct_mark)),goto_table:1")
}

func testNXExtensionsTest11(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	brName := ovsBr.OvsBridgeName
	status := ofApp.Switch.CheckStatus(1)
	assert.True(t, status, "Failed to check Switch status.")
	//Test match: reg1=0x12/0xffff
	reg1 := &NXRegister{
		ID:    1,
		Data:  uint32(0x12),
		Range: openflow15.NewNXRange(0, 15),
	}
	var regs = []*NXRegister{reg1}
	flow11, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		NxRegs:    regs,
	})
	require.NoError(t, err)
	err = flow11.ConnTrack(true, false, nil, nil)
	require.NoError(t, err, "Failed to apply dec_ttl action")
	verifyFlowInstallAndDelete(t, flow11, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,reg1=0x12/0xffff",
		"ct(commit),goto_table:1")
}

func testNXExtensionsTest12(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	brName := ovsBr.OvsBridgeName
	//Test match: ct_mark=0x20/0x20
	var mask = uint32(0x20)
	flow12, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		Ethertype:  0x0800,
		CtMark:     uint32(0x20),
		CtMarkMask: &mask,
	})
	require.NoError(t, err)
	verifyFlowInstallAndDelete(t, flow12, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ct_mark=0x20/0x20,ip",
		"goto_table:1")
}

func testNXExtensionsTest13(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	// Test group
	brName := ovsBr.OvsBridgeName
	groupId := uint32(1)

	group1 := newGroup(groupId, GroupSelect, ofApp.Switch)

	natAction := openflow15.NewNXActionCTNAT()
	assert.Nil(t, natAction.SetSNAT(), "Failed to set SNAT action")
	assert.Nil(t, natAction.SetRandom(), "Failed to set random action")
	natAction.SetRangeIPv4Min(net.ParseIP("10.0.0.240"))
	ctAction := openflow15.NewNXActionConnTrack()
	ctAction.Commit()
	ctAction.AddAction(natAction)
	bkt := openflow15.NewBucket(50)
	bkt.AddAction(ctAction)
	group1.AddBuckets(bkt)
	err := group1.Install()
	assert.NoError(t, err, "Failed to install group entry")
	verifyGroup(t, brName, group1, "select", "bucket=bucket_id:50,actions=ct(commit,nat(src=10.0.0.240,random))", true)

	// Install flow and refer to group
	inPort8 := uint32(10)
	flow13, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort8,
	})
	require.NoError(t, err)
	verifyFlowInstallAndDelete(t, flow13, group1, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=10",
		"group:1")
	group1.Delete()
	verifyGroup(t, brName, group1, "select", "bucket=bucket_id:50,actions=ct(commit,nat(src=10.0.0.240,random))", false)
}

func testNXExtensionsWithOFApplication(ofApp *OfActor, ovsBr *OvsDriver, t *testing.T) {
	brName := ovsBr.OvsBridgeName
	log.Infof("Enable monitor flows on table %d in bridge %s", ofApp.inputTable.TableId, brName)
	ofApp.Switch.EnableMonitor()

	testNXExtensionsTest1(ofApp, ovsBr, t)
	testNXExtensionsTest2_1(ofApp, ovsBr, t)
	testNXExtensionsTest2_2(ofApp, ovsBr, t)
	testNXExtensionsTest3(ofApp, ovsBr, t)
	testNXExtensionsTest4(ofApp, ovsBr, t)
	testNXExtensionsTest5(ofApp, ovsBr, t)
	testNXExtensionsTest6(ofApp, ovsBr, t)
	testNXExtensionsTest7(ofApp, ovsBr, t)
	testNXExtensionsTest8(ofApp, ovsBr, t)
	testNXExtensionsTest9(ofApp, ovsBr, t)
	testNXExtensionsTest10(ofApp, ovsBr, t)
	testNXExtensionsTest11(ofApp, ovsBr, t)
	testNXExtensionsTest12(ofApp, ovsBr, t)
	testNXExtensionsTest13(ofApp, ovsBr, t)
}

func verifyNewFlowInstallAndDelete(t *testing.T, flow *Flow, br string, tableID uint8, matchStr string, actionStr string) {
	err := flow.Send(openflow15.FC_ADD)
	assert.NoError(t, err, "Error installing flow")
	time.Sleep(11 * time.Second)
	flow.MonitorRealizeStatus()
	// verify metadata action exists
	assert.Truef(t, ofctlDumpFlowMatch(br, int(tableID), matchStr, actionStr), "br: %s, target flow not found on OVS, match: %s, actions: %s", br, matchStr, actionStr)
	assert.Truef(t, flow.IsRealized(), "Failed to realize flow status, match: %s, actions: %s", matchStr, actionStr)

	// delete the flow
	err = flow.Send(openflow15.FC_DELETE_STRICT)
	assert.NoError(t, err, "Error deleting the flow")

	// Make sure they are really gone
	assert.Falsef(t, ofctlDumpFlowMatch(br, int(tableID), matchStr, actionStr), "br: %s, target flow still found on OVS after deleting it: match: %s, actions: %s", br, matchStr, actionStr)
}

func verifyFlowInstallAndDelete(t *testing.T, flow *Flow, nextElem FgraphElem, br string, tableID uint8, matchStr string, actionStr string) {
	// install it
	err := flow.Next(nextElem)
	assert.NoError(t, err, "Error install flow")
	flow.MonitorRealizeStatus()
	time.Sleep(8 * time.Second)
	// verify metadata action exists
	assert.Truef(t, ofctlDumpFlowMatch(br, int(tableID), matchStr, actionStr), "br: %s, target flow not found on OVS, match: %s, actions: %s", br, matchStr, actionStr)
	assert.Truef(t, flow.IsRealized(), "Failed to realize flow status, match: %s, actions: %s", matchStr, actionStr)

	// delete the flow
	err = flow.Delete()
	assert.NoError(t, err, "Error deleting the flow")

	// Make sure they are really gone
	assert.Falsef(t, ofctlDumpFlowMatch(br, int(tableID), matchStr, actionStr), "br: %s, target flow still found on OVS after deleting it: match: %s, actions: %s", br, matchStr, actionStr)
}

func verifyGroup(t *testing.T, br string, group *Group, groupType string, buckets string, expectExists bool) {
	// dump groups
	groupList, err := ofctlGroupDump(br)
	assert.NoError(t, err, "Error dumping flows")
	groupStr := fmt.Sprintf("group_id=%d,type=%s,%s", group.ID, groupType, buckets)
	found := false
	for _, groupEntry := range groupList {
		log.Debugf("Looking for %s in %s", groupStr, groupEntry)
		if strings.Contains(groupEntry, groupStr) {
			found = true
			break
		}
	}
	assert.Equalf(t, expectExists, found, "br %s, failed to find group entry %s", br, groupStr)
}

// dump the groups and parse the Output
func ofctlGroupDump(brName string) ([]string, error) {
	groupDump, err := runOfctlCmd("dump-groups", brName)
	if err != nil {
		log.Errorf("Error running dump-groups on %s: %v", brName, err)
		return nil, err
	}

	log.Debugf("Group dump: %s", groupDump)
	groupOutStr := string(groupDump)
	groupDb := strings.Split(groupOutStr, "\n")[1:]

	log.Debugf("groupList: %+v", groupDb)

	return groupDb, nil
}

// Test flows using write_actions
func TestWriteactionsFlows(t *testing.T) {
	brName := ovsDriver.OvsBridgeName
	log.Infof("Enable monitor flows on table %d in bridge %s", ofActor.inputTable.TableId, brName)
	ofActor.Switch.EnableMonitor()

	// Test dnatTable flow using write_actions
	ipDa1 := net.ParseIP("10.96.0.0")
	ipAddrMask1 := net.ParseIP("255.240.0.0")
	flow1 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  200,
			Ethertype: 0x0800,
			IpDa:      &ipDa1,
			IpDaMask:  &ipAddrMask1,
		},
	}

	rng1 := openflow15.NewNXRange(16, 16)
	loadReg1, err := NewNXLoadAction("NXM_NX_REG0", uint64(1), rng1)
	require.NoError(t, err)
	flow1.ApplyActions([]OFAction{loadReg1})
	outputAction1 := NewOutputPort(uint32(1))
	flow1.WriteActions([]OFAction{outputAction1})
	flow1.Goto(ofActor.nextTable.TableId)
	verifyNewFlowInstallAndDelete(t, flow1, brName, ofActor.inputTable.TableId,
		"priority=200,ip,nw_dst=10.96.0.0/12",
		"load:0x1->NXM_NX_REG0[16],write_actions(output:1),goto_table:1")

	// Test l3ForwardingTable flow using write_actions
	ipDa2 := net.ParseIP("172.30.0.0")
	ipAddrMask2 := net.ParseIP("255.255.255.0")
	flow2 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:  200,
			Ethertype: 0x0800,
			IpDa:      &ipDa2,
			IpDaMask:  &ipAddrMask2,
		},
	}
	decTTLAction2 := &DecTTLAction{}

	srcMac2, _ := net.ParseMAC("11:11:11:11:11:11")
	srcMacAction2 := &SetSrcMACAction{MAC: srcMac2}

	dstMac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMacAction2 := &SetDstMACAction{MAC: dstMac2}

	rng2 := openflow15.NewNXRange(16, 16)
	loadReg2, err := NewNXLoadAction("NXM_NX_REG0", uint64(1), rng2)

	ipTunnelDa2 := net.ParseIP("192.168.20.1")
	tunnelDstAction := &SetTunnelDstAction{IP: ipTunnelDa2}

	flow2.ApplyActions([]OFAction{decTTLAction2, srcMacAction2, dstMacAction2, loadReg2, tunnelDstAction})

	outputAction2 := NewOutputPort(uint32(1))
	flow2.WriteActions([]OFAction{outputAction2})
	flow2.Goto(ofActor.nextTable.TableId)
	require.NoError(t, err)
	verifyNewFlowInstallAndDelete(t, flow2, brName, ofActor.inputTable.TableId,
		"priority=200,ip,nw_dst=172.30.0.0/24",
		"dec_ttl,set_field:11:11:11:11:11:11->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,load:0x1->NXM_NX_REG0[16],set_field:192.168.20.1->tun_dst,write_actions(output:1),goto_table:1")

	// Test l2ForwardingCalcTable flow using write_actions
	macDa3, _ := net.ParseMAC("11:11:11:11:11:11")

	flow3 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority: 200,
			MacDa:    &macDa3,
		},
	}

	rng3 := openflow15.NewNXRange(16, 16)
	loadReg3, err := NewNXLoadAction("NXM_NX_REG0", uint64(1), rng3)

	flow3.ApplyActions([]OFAction{loadReg3})

	outputAction3 := NewOutputPort(uint32(1))
	flow3.WriteActions([]OFAction{outputAction3})
	flow3.Goto(ofActor.nextTable.TableId)
	require.NoError(t, err)
	verifyNewFlowInstallAndDelete(t, flow3, brName, ofActor.inputTable.TableId,
		"priority=200,dl_dst=11:11:11:11:11:11",
		"load:0x1->NXM_NX_REG0[16],write_actions(output:1),goto_table:1")

	// Test ingressrule table flow with actset_output
	actsetOutput4 := uint32(105)
	flow4 := &Flow{
		Table: ofActor.inputTable,
		Match: FlowMatch{
			Priority:     200,
			Ethertype:    0x0800,
			ActsetOutput: actsetOutput4,
		},
	}

	conjunction4, err := NewNXConjunctionAction(uint32(101), uint8(2), uint8(3))
	require.NoError(t, err)
	flow4.ApplyActions([]OFAction{conjunction4})

	verifyNewFlowInstallAndDelete(t, flow4, brName, ofActor.inputTable.TableId,
		"priority=200,actset_output=105,ip",
		"conjunction(101,2/3)")

}
