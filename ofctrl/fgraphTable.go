/*
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

// This file implements the forwarding graph API for the table

import (
	"fmt"
	"sync"

	"antrea.io/libOpenflow/openflow15"

	log "github.com/sirupsen/logrus"
)

// Fgraph table element
type Table struct {
	Switch  *OFSwitch
	TableId uint8
	flowDb  map[string]*Flow // database of flow entries
	lock    sync.Mutex       // lock flowdb modification
}

// Fgraph element type for table
func (t *Table) Type() string {
	return "table"
}

// instruction set for table element
func (t *Table) GetFlowInstr() openflow15.Instruction {
	return openflow15.NewInstrGotoTable(t.TableId)
}

// FIXME: global unique flow cookie
var globalFlowID uint64 = 1

// Create a new flow on the table
func (t *Table) NewFlow(match FlowMatch) (*Flow, error) {
	// modifications to flowdb requires a lock
	t.lock.Lock()
	defer t.lock.Unlock()

	flow := new(Flow)
	flow.Table = t
	flow.Match = match
	flow.isInstalled = false
	flow.flowActions = make([]*FlowAction, 0)

	log.Debugf("Creating new flow for match: %+v", match)

	// See if the flow already exists
	flowKey := flow.flowKey()
	if t.flowDb[flowKey] != nil {
		log.Errorf("Flow %s already exists", flowKey)
		return nil, fmt.Errorf("Flow %s already exists", flowKey)
	}

	log.Debugf("Added flow: %s", flowKey)

	// Save it in DB. We dont install the flow till its next graph elem is set
	t.flowDb[flowKey] = flow

	return flow, nil
}

// Delete a flow from the table
func (t *Table) DeleteFlow(flowKey string) error {
	// modifications to flowdb requires a lock
	t.lock.Lock()
	defer t.lock.Unlock()

	// first empty it and then delete it.
	t.flowDb[flowKey] = nil
	delete(t.flowDb, flowKey)

	log.Debugf("Deleted flow: %s", flowKey)

	return nil
}

// Delete the table
func (t *Table) Delete() error {
	// FIXME: Delete the table
	return nil
}

func NewTable(tableId uint8, sw *OFSwitch) *Table {
	table := new(Table)
	table.Switch = sw
	table.TableId = tableId
	return table
}
