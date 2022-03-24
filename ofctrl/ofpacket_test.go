// #nosec G404: random number generator not used for security purposes
package ofctrl

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type packetApp struct {
	*OfActor
	pktCh chan *PacketIn
}

func (p *packetApp) PacketRcvd(sw *OFSwitch, pkt *PacketIn) {
	p.pktInCount += 1
	p.pktCh <- pkt
}

func TestGetNXRangeFromUint32Mask(t *testing.T) {
	r := openflow15.NewNXRange(0, 4)
	oriOfsNbits := r.ToOfsBits()
	mask := r.ToUint32Mask()
	r2 := getNXRangeFromUint32Mask(mask)
	newOfsNbits := r2.ToOfsBits()
	assert.Equal(t, oriOfsNbits, newOfsNbits)
}

func TestPacketIn_PacketOut(t *testing.T) {
	app := new(packetApp)
	app.OfActor = new(OfActor)
	app.pktCh = make(chan *PacketIn)
	ctrl := NewController(app)
	brName := "br4pkt"
	ovsBr := prepareControllerAndSwitch(t, app.OfActor, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()

	assert.Equal(t, 0, app.pktInCount)
	testPacketInOut(t, app, brName, false)
	assert.Equal(t, 1, app.pktInCount)
}

func TestPacketIn_PacketOut_IPv6(t *testing.T) {
	app := new(packetApp)
	app.OfActor = new(OfActor)
	app.pktCh = make(chan *PacketIn)
	ctrl := NewController(app)
	brName := "br4pktv6"
	ovsBr := prepareControllerAndSwitch(t, app.OfActor, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()

	assert.Equal(t, 0, app.pktInCount)
	testPacketInOut(t, app, brName, true)
	assert.Equal(t, 1, app.pktInCount)
}

func TestNxOutputAndSendController(t *testing.T) {
	app := new(packetApp)
	app.OfActor = new(OfActor)
	app.pktCh = make(chan *PacketIn)
	ctrl := NewController(app)
	brName := "br4sendcontroller"
	ovsBr := prepareControllerAndSwitch(t, app.OfActor, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()

	app.Switch.EnableMonitor()
	ofSwitch := app.Switch
	table0 := ofSwitch.DefaultTable()
	srcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	flow1 := &Flow{
		Table: table0,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMAC,
		},
	}
	err := flow1.OutputReg("NXM_NX_REG0", 0, 31)
	require.Nil(t, err)
	err = flow1.Controller(0x1)
	require.Nil(t, err)
	flow1.Send(openflow15.FC_ADD)
	verifyFlowInstallAndDelete(t, flow1, NewEmptyElem(), brName, table0.TableId,
		"priority=100,ip,dl_src=11:22:33:44:55:66",
		fmt.Sprintf("output:NXM_NX_REG0[],controller(max_len=128,id=%d)", app.Switch.ctrlID))
}

func testPacketInOut(t *testing.T, ofApp *packetApp, brName string, ipv6 bool) {
	log.Infof("Enable monitor flows on table %d in bridge %s", ofApp.inputTable.TableId, brName)
	ofApp.Switch.EnableMonitor()

	ofSwitch := ofApp.Switch

	srcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	dstMAC, _ := net.ParseMAC("66:55:44:33:22:11")
	var srcIP net.IP
	var dstIP net.IP
	if ipv6 {
		srcIP = net.ParseIP("2001::1")
		dstIP = net.ParseIP("2002::1")
	} else {
		srcIP = net.ParseIP("1.1.1.2")
		dstIP = net.ParseIP("2.2.2.1")
	}
	dstPort := uint16(1234)

	table0 := ofSwitch.DefaultTable()
	table1 := ofApp.nextTable
	flow0 := &Flow{
		Table: table0,
		Match: FlowMatch{
			Priority: 100,
		},
	}
	flow0.ApplyActions([]OFAction{
		NewResubmit(nil, &table1.TableId),
	})
	flow0.Send(openflow15.FC_ADD)

	var ethertype uint16
	if ipv6 {
		ethertype = protocol.IPv6_MSG
	} else {
		ethertype = protocol.IPv4_MSG
	}

	flow1 := &Flow{
		Table: table1,
		Match: FlowMatch{
			Priority:  100,
			Ethertype: ethertype,
			MacSa:     &srcMAC,
			MacDa:     &dstMAC,
			IpSa:      &srcIP,
			IpDa:      &dstIP,
			IpProto:   IP_PROTO_TCP,
			DstPort:   dstPort,
		},
	}
	rng0 := openflow15.NewNXRange(0, 15)
	rng1 := openflow15.NewNXRange(16, 31)
	rng2 := openflow15.NewNXRange(8, 23)
	act1, err := NewNXLoadAction("NXM_NX_REG0", uint64(0x1234), rng0)
	require.Nil(t, err)
	act2, err := NewNXLoadAction("NXM_NX_REG0", uint64(0x5678), rng1)
	require.Nil(t, err)
	act3, err := NewNXLoadAction("NXM_NX_REG1", uint64(0xaaaa), rng2)
	require.Nil(t, err)
	var expectTunDst net.IP
	if ipv6 {
		expectTunDst = net.ParseIP("2000::10")
	} else {
		expectTunDst = net.ParseIP("10.10.10.10")
	}
	act5 := &SetTunnelDstAction{IP: expectTunDst}
	cxControllerAct := &NXController{ControllerID: ofSwitch.ctrlID}
	flow1.ApplyActions([]OFAction{act1, act2, act3, act5, cxControllerAct})
	flow1.Send(openflow15.FC_ADD)

	act4, err := NewNXLoadAction("NXM_NX_REG3", uint64(0xaaaa), rng2)
	require.NoError(t, err)
	packetOut := generateTCPPacketOut(srcMAC, dstMAC, srcIP, dstIP, dstPort, 0, nil, []OFAction{act4})
	if ipv6 {
		assert.NotNil(t, packetOut.IPv6Header)
		assert.Nil(t, packetOut.IPHeader)
		assert.Equal(t, dstIP, packetOut.IPv6Header.NWDst)
	} else {
		assert.NotNil(t, packetOut.IPHeader)
		assert.Nil(t, packetOut.IPv6Header)
	}
	ofSwitch.Send(packetOut.GetMessage())

	var pktIn *PacketIn
	select {
	case pktIn = <-ofApp.pktCh:
	case <-time.After(10 * time.Second):
		t.Fatalf("PacketIn timeout")
	}
	matchers := pktIn.GetMatches()
	reg0Match := matchers.GetMatchByName("NXM_NX_REG0")
	assert.NotNil(t, reg0Match)
	reg0Value, ok := reg0Match.GetValue().(*NXRegister)
	assert.True(t, ok)
	reg0prev := GetUint32ValueWithRange(reg0Value.Data, rng0)
	assert.Equal(t, uint32(0x1234), reg0prev)
	reg0last := GetUint32ValueWithRange(reg0Value.Data, rng1)
	assert.Equal(t, uint32(0x5678), reg0last)
	reg1Match := matchers.GetMatchByName("NXM_NX_REG1")
	assert.NotNil(t, reg1Match)
	reg1Value, ok := reg1Match.GetValue().(*NXRegister)
	assert.True(t, ok)
	reg1prev := GetUint32ValueWithRange(reg1Value.Data, rng2)
	assert.Equal(t, uint32(0xaaaa), reg1prev)
	reg2Match := matchers.GetMatchByName("NXM_NX_REG2")
	assert.Nil(t, reg2Match)
	var tunDstMatch *MatchField
	if ipv6 {
		tunDstMatch = matchers.GetMatchByName("NXM_NX_TUN_IPV6_DST")
	} else {
		tunDstMatch = matchers.GetMatchByName("NXM_NX_TUN_IPV4_DST")
	}
	assert.NotNil(t, tunDstMatch)
	tunDst := tunDstMatch.GetValue().(net.IP)
	assert.Equal(t, expectTunDst, tunDst)
	if ipv6 {
		assert.Equal(t, uint16(protocol.IPv6_MSG), pktIn.Data.(*protocol.Ethernet).Ethertype)
		var ipv6Obj protocol.IPv6
		ipv6Bytes, err := pktIn.Data.(*protocol.Ethernet).Data.(*protocol.IPv6).MarshalBinary()
		assert.Nil(t, err)
		assert.Nil(t, ipv6Obj.UnmarshalBinary(ipv6Bytes))
		assert.Equal(t, srcIP, ipv6Obj.NWSrc)
		assert.Equal(t, dstIP, ipv6Obj.NWDst)
		assert.Equal(t, uint8(IP_PROTO_TCP), ipv6Obj.NextHeader)
		var tcpObj protocol.TCP
		assert.Nil(t, tcpObj.UnmarshalBinary(ipv6Obj.Data.(*util.Buffer).Bytes()))
		assert.Equal(t, dstPort, tcpObj.PortDst)
	} else {
		assert.Equal(t, dstIP.To4(), pktIn.Data.(*protocol.Ethernet).Data.(*protocol.IPv4).NWDst)
	}
}

func generateTCPPacketOut(srcMAC, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP, dstPort, srcPort uint16, outputPort *uint32, actions []OFAction) *PacketOut {
	var outPort uint32
	if outputPort == nil {
		outPort = openflow15.P_TABLE
	} else {
		outPort = *outputPort
	}
	if dstPort == 0 {
		dstPort = uint16(rand.Uint32())
	}
	if srcPort == 0 {
		srcPort = uint16(rand.Uint32())
	}
	pktOut := GenerateTCPPacket(srcMAC, dstMAC, srcIP, dstIP, dstPort, srcPort, nil)
	pktOut.InPort = openflow15.P_CONTROLLER
	pktOut.OutPort = outPort
	if actions != nil {
		pktOut.Actions = actions
	}
	return pktOut
}

// keeping this in case it is useful later
//nolint:deadcode
func generatePacketOut(srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP, outputPort *uint32, actions []OFAction) *PacketOut {
	var outPort uint32
	if outputPort == nil {
		outPort = openflow15.P_TABLE
	} else {
		outPort = *outputPort
	}
	pktOut := GenerateSimpleIPPacket(srcMAC, dstMAC, srcIP, dstIP)
	pktOut.InPort = openflow15.P_CONTROLLER
	pktOut.OutPort = outPort
	if actions != nil {
		pktOut.Actions = actions
	}
	return pktOut
}
