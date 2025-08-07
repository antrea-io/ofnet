package ofctrl

import "antrea.io/libOpenflow/openflow15"

// This file implements the forwarding graph API for output to NX register element

type NXOutput struct {
	field      *openflow15.MatchField // Target OXM/NXM field
	fieldRange *openflow15.NXRange    // Field range of target register to output
}

// Return a NXOutput action
func (o *NXOutput) GetActionMessage() openflow15.Action {
	ofsNbits := o.fieldRange.ToOfsBits()
	targetField := o.field
	// Create NX output Register action
	return openflow15.NewOutputFromField(targetField, ofsNbits)
}

func (o *NXOutput) GetActionType() string {
	return ActTypeNXOutput
}

func NewNXOutput(name string, start int, end int) (*NXOutput, error) {
	field, err := openflow15.FindFieldHeaderByName(name, false)
	if err != nil {
		return nil, err
	}
	fieldRange := openflow15.NewNXRange(start, end)
	return &NXOutput{
		field:      field,
		fieldRange: fieldRange,
	}, nil
}
