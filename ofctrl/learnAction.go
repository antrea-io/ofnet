package ofctrl

import "antrea.io/libOpenflow/openflow15"

type FlowLearn struct {
	idleTimeout    uint16
	hardTimeout    uint16
	priority       uint16
	cookie         uint64
	flags          uint16
	tableID        uint8
	finIdleTimeout uint16
	finHardTimeout uint16
	specs          []*openflow15.NXLearnSpec
}

type LearnField struct {
	Name  string
	Start uint16
}

func (f *LearnField) getNXLearnSpecField() (*openflow15.NXLearnSpecField, error) {
	field, err := openflow15.FindFieldHeaderByName(f.Name, true)
	if err != nil {
		return nil, err
	}
	return &openflow15.NXLearnSpecField{
		Field: field,
		Ofs:   f.Start,
	}, nil
}

func (l *FlowLearn) AddMatch(matchField *LearnField, learnBits uint16, fromField *LearnField, fromValue []byte) error {
	dstField, err := matchField.getNXLearnSpecField()
	if err != nil {
		return err
	}
	var spec *openflow15.NXLearnSpec
	if fromValue != nil {
		header := openflow15.NewLearnHeaderMatchFromValue(learnBits)
		spec = getNXLearnSpecWithValue(header, dstField, fromValue)
	} else {
		header := openflow15.NewLearnHeaderMatchFromField(learnBits)
		srcField, err := fromField.getNXLearnSpecField()
		if err != nil {
			return err
		}
		spec = getNXLearnSpecWithField(header, dstField, srcField)
	}
	l.specs = append(l.specs, spec)
	return nil
}

func (l *FlowLearn) AddLoadAction(toField *LearnField, learnBits uint16, fromField *LearnField, fromValue []byte) error {
	dstField, err := toField.getNXLearnSpecField()
	if err != nil {
		return err
	}
	var spec *openflow15.NXLearnSpec
	if fromValue != nil {
		header := openflow15.NewLearnHeaderLoadFromValue(learnBits)
		spec = getNXLearnSpecWithValue(header, dstField, fromValue)
	} else {
		header := openflow15.NewLearnHeaderLoadFromField(learnBits)
		srcField, err := fromField.getNXLearnSpecField()
		if err != nil {
			return err
		}
		spec = getNXLearnSpecWithField(header, dstField, srcField)
	}
	l.specs = append(l.specs, spec)
	return nil
}

func (l *FlowLearn) AddOutputAction(toField *LearnField, learnBits uint16) error {
	srcField, err := toField.getNXLearnSpecField()
	if err != nil {
		return err
	}
	header := openflow15.NewLearnHeaderOutputFromField(learnBits)
	spec := &openflow15.NXLearnSpec{
		Header:   header,
		SrcField: srcField,
	}
	l.specs = append(l.specs, spec)
	return nil
}

func (l *FlowLearn) GetActionMessage() openflow15.Action {
	learnAction := openflow15.NewNXActionLearn()
	learnAction.IdleTimeout = l.idleTimeout
	learnAction.HardTimeout = l.hardTimeout
	learnAction.Priority = l.priority
	learnAction.Cookie = l.cookie
	learnAction.Flags = l.flags
	learnAction.TableID = l.tableID
	learnAction.FinIdleTimeout = l.finIdleTimeout
	learnAction.FinHardTimeout = l.finHardTimeout
	learnAction.LearnSpecs = l.specs
	return learnAction
}

func (l *FlowLearn) GetActionType() string {
	return ActTypeNXLearn
}

func (l *FlowLearn) DeleteLearnedFlowsAfterDeletion() {
	l.flags |= openflow15.NX_LEARN_F_DELETE_LEARNED
}

func NewLearnAction(tableID uint8, priority, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout uint16, cookieID uint64) *FlowLearn {
	return &FlowLearn{
		idleTimeout:    idleTimeout,
		hardTimeout:    hardTimeout,
		priority:       priority,
		cookie:         cookieID,
		tableID:        tableID,
		finIdleTimeout: finIdleTimeout,
		finHardTimeout: finHardTimeout,
	}
}

func getNXLearnSpecWithValue(header *openflow15.NXLearnSpecHeader, dstField *openflow15.NXLearnSpecField, value []byte) *openflow15.NXLearnSpec {
	return &openflow15.NXLearnSpec{
		Header:   header,
		DstField: dstField,
		SrcValue: value,
	}
}

func getNXLearnSpecWithField(header *openflow15.NXLearnSpecHeader, dstField *openflow15.NXLearnSpecField, srcField *openflow15.NXLearnSpecField) *openflow15.NXLearnSpec {
	return &openflow15.NXLearnSpec{
		Header:   header,
		SrcField: srcField,
		DstField: dstField,
	}
}
