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

func (g *Group) Type() string {
	return "group"
}

func (g *Group) GetActionMessage() openflow15.Action {
	return openflow15.NewActionGroup(g.ID)
}

func (g *Group) GetActionType() string {
	return ActTypeGroup
}

func (g *Group) GetFlowInstr() openflow15.Instruction {
	groupInstr := openflow15.NewInstrApplyActions()
	groupAct := g.GetActionMessage()
	// Add group action to the instruction
	groupInstr.AddAction(groupAct, false)
	return groupInstr
}

func (g *Group) AddBuckets(buckets ...*openflow15.Bucket) {
	if g.Buckets == nil {
		g.Buckets = make([]*openflow15.Bucket, 0)
	}
	g.Buckets = append(g.Buckets, buckets...)
	if g.isInstalled {
		g.Install()
	}
}

func (g *Group) ResetBuckets(buckets ...*openflow15.Bucket) {
	g.Buckets = make([]*openflow15.Bucket, 0)
	g.Buckets = append(g.Buckets, buckets...)
	if g.isInstalled {
		g.Install()
	}
}

func (g *Group) AddProperty(prop util.Message) {
	g.Properties = append(g.Properties, prop)
	if g.isInstalled {
		g.Install()
	}
}

func (g *Group) Install() error {
	command := openflow15.OFPGC_ADD
	if g.isInstalled {
		command = openflow15.OFPGC_MODIFY
	}
	groupMod := g.getGroupModMessage(command)

	if err := g.Switch.Send(groupMod); err != nil {
		return err
	}

	// Mark it as installed
	g.isInstalled = true

	return nil
}

func (g *Group) getGroupModMessage(command int) *openflow15.GroupMod {
	groupMod := openflow15.NewGroupMod()
	groupMod.GroupId = g.ID
	groupMod.Command = uint16(command)

	switch g.GroupType {
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
		groupMod.Properties = append(groupMod.Properties, g.Properties...)
	}

	for _, bkt := range g.Buckets {
		// Add the bucket to group
		groupMod.AddBucket(*bkt)
	}

	if command == openflow15.OFPGC_INSERT_BUCKET {
		groupMod.CommandBucketId = openflow15.OFPG_BUCKET_LAST
	}

	return groupMod
}

func (g *Group) GetBundleMessage(command int) *GroupBundleMessage {
	groupMod := g.getGroupModMessage(command)
	return &GroupBundleMessage{groupMod}
}

func (g *Group) Delete() error {
	if g.isInstalled {
		groupMod := openflow15.NewGroupMod()
		groupMod.GroupId = g.ID
		groupMod.Command = openflow15.OFPGC_DELETE
		if err := g.Switch.Send(groupMod); err != nil {
			return err
		}
		// Mark it as unInstalled
		g.isInstalled = false
	}

	// Delete group from switch cache
	return g.Switch.DeleteGroup(g.ID)
}

func NewGroup(groupId uint32, groupType GroupType, sw *OFSwitch) *Group {
	return &Group{
		ID:        groupId,
		GroupType: groupType,
		Switch:    sw,
	}
}
