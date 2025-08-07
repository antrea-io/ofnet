package ofctrl

import (
	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
)

type MeterFlag int
type MeterType uint16

const (
	MeterKbps  MeterFlag = 0b0001
	MeterPktps MeterFlag = 0b0010
	MeterBurst MeterFlag = 0b0100
	MeterStats MeterFlag = 0b1000

	MeterDrop         MeterType = 1      /* Drop packet. */
	MeterDSCPRemark   MeterType = 2      /* Remark DSCP in the IP header. */
	MeterExperimenter MeterType = 0xFFFF /* Experimenter meter band. */
)

type MeterBundleMessage struct {
	message *openflow15.MeterMod
}

func (m *MeterBundleMessage) resetXid(xid uint32) util.Message {
	m.message.Xid = xid
	return m.message
}

func (m *MeterBundleMessage) getXid() uint32 {
	return m.message.Xid
}

func (m *MeterBundleMessage) GetMessage() util.Message {
	return m.message
}

type Meter struct {
	Switch      *OFSwitch
	ID          uint32
	Flags       MeterFlag
	MeterBands  []*util.Message
	isInstalled bool
}

func (m *Meter) Type() string {
	return "meter"
}

func (m *Meter) AddMeterBand(meterBands ...*util.Message) {
	if m.MeterBands == nil {
		m.MeterBands = make([]*util.Message, 0)
	}
	m.MeterBands = append(m.MeterBands, meterBands...)
	if m.isInstalled {
		m.Install()
	}
}

func (m *Meter) Install() error {
	command := openflow15.MC_ADD
	if m.isInstalled {
		command = openflow15.MC_MODIFY
	}
	meterMod := m.getMeterModMessage(command)

	if err := m.Switch.Send(meterMod); err != nil {
		return err
	}

	// Mark it as installed
	m.isInstalled = true

	return nil
}

func (m *Meter) getMeterModMessage(command int) *openflow15.MeterMod {
	meterMod := openflow15.NewMeterMod()
	meterMod.MeterId = m.ID
	meterMod.Flags = uint16(m.Flags)

	for _, mb := range m.MeterBands {
		// Add the meterBands to meter
		meterMod.AddMeterBand(*mb)
	}
	meterMod.Command = uint16(command)

	return meterMod
}

func (m *Meter) GetBundleMessage(command int) *MeterBundleMessage {
	meterMod := m.getMeterModMessage(command)
	return &MeterBundleMessage{meterMod}
}

func (m *Meter) Delete() error {
	if m.isInstalled {
		meterMod := openflow15.NewMeterMod()
		meterMod.MeterId = m.ID
		meterMod.Command = openflow15.MC_DELETE
		if err := m.Switch.Send(meterMod); err != nil {
			return err
		}
		// Mark it as unInstalled
		m.isInstalled = false
	}

	// Delete meter from switch cache
	return m.Switch.DeleteMeter(m.ID)
}

func NewMeter(meterId uint32, flags MeterFlag, sw *OFSwitch) *Meter {
	return &Meter{
		ID:     meterId,
		Flags:  flags,
		Switch: sw,
	}
}
