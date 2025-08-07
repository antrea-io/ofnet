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

// This file implements the forwarding graph API for the switch

import (
	"errors"

	"antrea.io/libOpenflow/openflow15"
)

// Initialize the fgraph elements on the switch
func (s *OFSwitch) initFgraph() {
	// Create the DBs
	s.tableDb = make(map[uint8]*Table)
	s.groupDb = make(map[uint32]*Group)
	s.meterDb = make(map[uint32]*Meter)
	s.outputPorts = make(map[uint32]*Output)

	// Create the table 0
	table := new(Table)
	table.Switch = s
	table.TableId = 0
	table.flowDb = make(map[string]*Flow)
	s.tableDb[0] = table

	// Create drop action
	dropAction := new(Output)
	dropAction.outputType = "drop"
	dropAction.portNo = openflow15.P_ANY
	s.dropAction = dropAction

	// create send to controller action
	sendToCtrler := new(Output)
	sendToCtrler.outputType = "toController"
	sendToCtrler.portNo = openflow15.P_CONTROLLER
	s.sendToCtrler = sendToCtrler

	// Create normal lookup action.
	normalLookup := new(Output)
	normalLookup.outputType = "normal"
	normalLookup.portNo = openflow15.P_NORMAL
	s.normalLookup = normalLookup
}

// Create a new table. return an error if it already exists
func (s *OFSwitch) NewTable(tableId uint8) (*Table, error) {
	s.tableDbMux.Lock()
	defer s.tableDbMux.Unlock()
	// Check the parameters
	if tableId == 0 {
		return nil, errors.New("Table 0 already exists")
	}

	// check if the table already exists
	if s.tableDb[tableId] != nil {
		return nil, errors.New("Table already exists")
	}

	// Create a new table
	table := NewTable(tableId, s)
	table.flowDb = make(map[string]*Flow)
	// Save it in the DB
	s.tableDb[tableId] = table

	return table, nil
}

// Delete a table.
// Return an error if there are fgraph nodes pointing at it
func (s *OFSwitch) DeleteTable(tableId uint8) error {
	// FIXME: to be implemented
	return nil
}

// GetTable Returns a table
func (s *OFSwitch) GetTable(tableId uint8) *Table {
	s.tableDbMux.Lock()
	defer s.tableDbMux.Unlock()
	return s.tableDb[tableId]
}

// Return table 0 which is the starting table for all packets
func (s *OFSwitch) DefaultTable() *Table {
	s.tableDbMux.Lock()
	defer s.tableDbMux.Unlock()
	return s.tableDb[0]
}

// Create a new group. return an error if it already exists
func (s *OFSwitch) NewGroup(groupId uint32, groupType GroupType) (*Group, error) {
	s.groupDbMux.Lock()
	defer s.groupDbMux.Unlock()
	// check if the group already exists
	if s.groupDb[groupId] != nil {
		return nil, errors.New("group already exists")
	}

	// Create a new group
	group := NewGroup(groupId, groupType, s)
	// Save it in the DB
	s.groupDb[groupId] = group

	return group, nil
}

// Delete a group.
// Return an error if there are flows refer pointing at it
func (s *OFSwitch) DeleteGroup(groupId uint32) error {
	s.groupDbMux.Lock()
	defer s.groupDbMux.Unlock()
	delete(s.groupDb, groupId)
	return nil
}

// GetGroup Returns a group
func (s *OFSwitch) GetGroup(groupId uint32) *Group {
	s.groupDbMux.Lock()
	defer s.groupDbMux.Unlock()
	return s.groupDb[groupId]
}

// Create a new meter. return an error if it already exists
func (s *OFSwitch) NewMeter(meterId uint32, flags MeterFlag) (*Meter, error) {
	s.meterDbMux.Lock()
	defer s.meterDbMux.Unlock()
	// check if the meter already exists
	if _, ok := s.meterDb[meterId]; ok {
		return nil, errors.New("meter already exists")
	}

	// Create a new meter
	meter := NewMeter(meterId, flags, s)
	// Save it in the DB
	s.meterDb[meterId] = meter

	return meter, nil
}

// Delete a meter.
// Return an error if there are flows refer pointing at it
func (s *OFSwitch) DeleteMeter(meterId uint32) error {
	s.meterDbMux.Lock()
	defer s.meterDbMux.Unlock()
	delete(s.meterDb, meterId)
	return nil
}

// GetGroup Returns a meter
func (s *OFSwitch) GetMeter(meterId uint32) *Meter {
	s.meterDbMux.Lock()
	defer s.meterDbMux.Unlock()
	return s.meterDb[meterId]
}

// Return a output graph element for the port
func (s *OFSwitch) OutputPort(portNo uint32) (*Output, error) {
	s.portMux.Lock()
	defer s.portMux.Unlock()

	if val, ok := s.outputPorts[portNo]; ok {
		return val, nil
	}

	// Create a new output element
	output := new(Output)
	output.outputType = "port"
	output.portNo = portNo

	// store all outputs in a DB
	s.outputPorts[portNo] = output

	return output, nil
}

// Return the drop graph element
func (s *OFSwitch) DropAction() *Output {
	return s.dropAction
}

// SendToController Return send to controller graph element
func (s *OFSwitch) SendToController() *Output {
	return s.sendToCtrler
}

// NormalLookup Return normal lookup graph element
func (s *OFSwitch) NormalLookup() *Output {
	return s.normalLookup
}

// FIXME: Unique group id for the flood entries
var uniqueGroupId uint32 = 1

// Create a new flood list
func (s *OFSwitch) NewFlood() (*Flood, error) {
	flood := new(Flood)

	flood.Switch = s
	flood.GroupId = uniqueGroupId
	uniqueGroupId += 1

	// Install it in HW right away
	flood.install()

	return flood, nil
}
