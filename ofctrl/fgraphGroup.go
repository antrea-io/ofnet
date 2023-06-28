package ofctrl

import (
	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
)

type GroupType int

const (
	GroupAll GroupType = iota
	GroupSelect
	GroupIndirect
	GroupFF
)

type GroupBundleMessage struct {
	message *openflow15.GroupMod
}

func (m *GroupBundleMessage) resetXid(xid uint32) util.Message {
	m.message.Xid = xid
	return m.message
}

func (m *GroupBundleMessage) getXid() uint32 {
	return m.message.Xid
}

func (m *GroupBundleMessage) GetMessage() util.Message {
	return m.message
}

type Group struct {
	Switch      *OFSwitch
	ID          uint32
	GroupType   GroupType
	Buckets     []*openflow15.Bucket
	Properties  []util.Message
	isInstalled bool
}

func (self *Group) Type() string {
	return "group"
}

func (self *Group) GetActionMessage() openflow15.Action {
	return openflow15.NewActionGroup(self.ID)
}

func (self *Group) GetActionType() string {
	return ActTypeGroup
}

func (self *Group) GetFlowInstr() openflow15.Instruction {
	groupInstr := openflow15.NewInstrApplyActions()
	groupAct := self.GetActionMessage()
	// Add group action to the instruction
	groupInstr.AddAction(groupAct, false)
	return groupInstr
}

func (self *Group) AddBuckets(buckets ...*openflow15.Bucket) {
	if self.Buckets == nil {
		self.Buckets = make([]*openflow15.Bucket, 0)
	}
	self.Buckets = append(self.Buckets, buckets...)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) ResetBuckets(buckets ...*openflow15.Bucket) {
	self.Buckets = make([]*openflow15.Bucket, 0)
	self.Buckets = append(self.Buckets, buckets...)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) AddProperty(prop util.Message) {
	self.Properties = append(self.Properties, prop)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) Install() error {
	command := openflow15.OFPGC_ADD
	if self.isInstalled {
		command = openflow15.OFPGC_MODIFY
	}
	groupMod := self.getGroupModMessage(command)

	if err := self.Switch.Send(groupMod); err != nil {
		return err
	}

	// Mark it as installed
	self.isInstalled = true

	return nil
}

func (self *Group) getGroupModMessage(command int) *openflow15.GroupMod {
	groupMod := openflow15.NewGroupMod()
	groupMod.GroupId = self.ID
	groupMod.Command = uint16(command)

	switch self.GroupType {
	case GroupAll:
		groupMod.Type = openflow15.GT_ALL
	case GroupSelect:
		groupMod.Type = openflow15.GT_SELECT
	case GroupIndirect:
		groupMod.Type = openflow15.GT_INDIRECT
	case GroupFF:
		groupMod.Type = openflow15.GT_FF
	}

	if command == openflow15.OFPGC_DELETE {
		return groupMod
	}

	if command == openflow15.OFPGC_ADD || command == openflow15.OFPGC_MODIFY {
		for _, prop := range self.Properties {
			groupMod.Properties = append(groupMod.Properties, prop)
		}
	}

	for _, bkt := range self.Buckets {
		// Add the bucket to group
		groupMod.AddBucket(*bkt)
	}

	if command == openflow15.OFPGC_INSERT_BUCKET {
		groupMod.CommandBucketId = openflow15.OFPG_BUCKET_LAST
	}

	return groupMod
}

func (self *Group) GetBundleMessage(command int) *GroupBundleMessage {
	groupMod := self.getGroupModMessage(command)
	return &GroupBundleMessage{groupMod}
}

func (self *Group) Delete() error {
	if self.isInstalled {
		groupMod := openflow15.NewGroupMod()
		groupMod.GroupId = self.ID
		groupMod.Command = openflow15.OFPGC_DELETE
		if err := self.Switch.Send(groupMod); err != nil {
			return err
		}
		// Mark it as unInstalled
		self.isInstalled = false
	}

	// Delete group from switch cache
	return self.Switch.DeleteGroup(self.ID)
}

func NewGroup(groupId uint32, groupType GroupType, sw *OFSwitch) *Group {
	return &Group{
		ID:        groupId,
		GroupType: groupType,
		Switch:    sw,
	}
}
