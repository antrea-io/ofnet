package ofctrl

import (
	"antrea.io/libOpenflow/openflow15"
)

// This file implements the forwarding graph API for empty element. It will return
// InstrActions as the value of GetFlowInstr, but without any reserved actions.

type EmptyElem struct {
}

// Fgraph element type for the NXOutput
func (e *EmptyElem) Type() string {
	return "empty"
}

// instruction set for NXOutput element
func (e *EmptyElem) GetFlowInstr() openflow15.Instruction {
	instr := openflow15.NewInstrApplyActions()
	return instr
}

func NewEmptyElem() *EmptyElem {
	return new(EmptyElem)
}
