package ofctrl

import "antrea.io/libOpenflow/openflow15"

// This file implements the forwarding graph API for the resubmit element

type Resubmit struct {
	ofport    uint16 // target ofport to resubmit
	nextTable uint8  // target table to resubmit
	withCT    bool   // with ct or not
}

// Fgraph element type for the Resubmit
func (self *Resubmit) Type() string {
	return "Resubmit"
}

// instruction set for resubmit element
func (self *Resubmit) GetFlowInstr() openflow15.Instruction {
	outputInstr := openflow15.NewInstrApplyActions()
	resubmitAct := self.GetActionMessage()
	outputInstr.AddAction(resubmitAct, false)
	return outputInstr
}

// Return a resubmit action (Used as a last action by flows in the table pipeline)
func (self *Resubmit) GetActionMessage() openflow15.Action {
	if self.withCT {
		return openflow15.NewNXActionResubmitTableCT(self.ofport, self.nextTable)
	} else {
		return openflow15.NewNXActionResubmitTableAction(self.ofport, self.nextTable)
	}
}

func (self *Resubmit) GetActionType() string {
	return ActTypeNXResubmit
}

func NewResubmit(inPort *uint16, table *uint8) *Resubmit {
	resubmit := new(Resubmit)
	if inPort == nil {
		resubmit.ofport = openflow15.OFPP_IN_PORT
	} else {
		resubmit.ofport = *inPort
	}
	if table == nil {
		resubmit.nextTable = openflow15.OFPTT_ALL
	} else {
		resubmit.nextTable = *table
	}
	resubmit.withCT = false
	return resubmit
}

func NewResubmitWithCT(inPort *uint16, table *uint8) *Resubmit {
	resubmit := NewResubmit(inPort, table)
	resubmit.withCT = true
	return resubmit
}
