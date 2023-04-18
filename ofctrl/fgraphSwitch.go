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
func (self *OFSwitch) initFgraph() {
	// Create the DBs
	self.tableDb = make(map[uint8]*Table)
	self.groupDb = make(map[uint32]*Group)
	self.meterDb = make(map[uint32]*Meter)
	self.outputPorts = make(map[uint32]*Output)

	// Create the table 0
	table := new(Table)
	table.Switch = self
	table.TableId = 0
	table.flowDb = make(map[string]*Flow)
	self.tableDb[0] = table

	// Create drop action
	dropAction := new(Output)
	dropAction.outputType = "drop"
	dropAction.portNo = openflow15.P_ANY
	self.dropAction = dropAction

	// create send to controller action
	sendToCtrler := new(Output)
	sendToCtrler.outputType = "toController"
	sendToCtrler.portNo = openflow15.P_CONTROLLER
	self.sendToCtrler = sendToCtrler

	// Create normal lookup action.
	normalLookup := new(Output)
	normalLookup.outputType = "normal"
	normalLookup.portNo = openflow15.P_NORMAL
	self.normalLookup = normalLookup
}

// Create a new table. return an error if it already exists
func (self *OFSwitch) NewTable(tableId uint8) (*Table, error) {
	self.tableDbMux.Lock()
	defer self.tableDbMux.Unlock()
	// Check the parameters
	if tableId == 0 {
		return nil, errors.New("Table 0 already exists")
	}

	// check if the table already exists
	if self.tableDb[tableId] != nil {
		return nil, errors.New("Table already exists")
	}

	// Create a new table
	table := new(Table)
	table.Switch = self
	table.TableId = tableId
	table.flowDb = make(map[string]*Flow)
	// Save it in the DB
	self.tableDb[tableId] = table

	return table, nil
}

// Delete a table.
// Return an error if there are fgraph nodes pointing at it
func (self *OFSwitch) DeleteTable(tableId uint8) error {
	// FIXME: to be implemented
	return nil
}

// GetTable Returns a table
func (self *OFSwitch) GetTable(tableId uint8) *Table {
	self.tableDbMux.Lock()
	defer self.tableDbMux.Unlock()
	return self.tableDb[tableId]
}

// Return table 0 which is the starting table for all packets
func (self *OFSwitch) DefaultTable() *Table {
	self.tableDbMux.Lock()
	defer self.tableDbMux.Unlock()
	return self.tableDb[0]
}

// Create a new group. return an error if it already exists
func (self *OFSwitch) NewGroup(groupId uint32, groupType GroupType) (*Group, error) {
	self.groupDbMux.Lock()
	defer self.groupDbMux.Unlock()
	// check if the group already exists
	if self.groupDb[groupId] != nil {
		return nil, errors.New("group already exists")
	}

	// Create a new group
	group := newGroup(groupId, groupType, self)
	// Save it in the DB
	self.groupDb[groupId] = group

	return group, nil
}

// Delete a group.
// Return an error if there are flows refer pointing at it
func (self *OFSwitch) DeleteGroup(groupId uint32) error {
	self.groupDbMux.Lock()
	defer self.groupDbMux.Unlock()
	delete(self.groupDb, groupId)
	return nil
}

// GetGroup Returns a group
func (self *OFSwitch) GetGroup(groupId uint32) *Group {
	self.groupDbMux.Lock()
	defer self.groupDbMux.Unlock()
	return self.groupDb[groupId]
}

// Create a new meter. return an error if it already exists
func (self *OFSwitch) NewMeter(meterId uint32, flags MeterFlag) (*Meter, error) {
	self.meterDbMux.Lock()
	defer self.meterDbMux.Unlock()
	// check if the meter already exists
	if _, ok := self.meterDb[meterId]; ok {
		return nil, errors.New("meter already exists")
	}

	// Create a new meter
	meter := newMeter(meterId, flags, self)
	// Save it in the DB
	self.meterDb[meterId] = meter

	return meter, nil
}

// Delete a meter.
// Return an error if there are flows refer pointing at it
func (self *OFSwitch) DeleteMeter(meterId uint32) error {
	self.meterDbMux.Lock()
	defer self.meterDbMux.Unlock()
	delete(self.meterDb, meterId)
	return nil
}

// GetGroup Returns a meter
func (self *OFSwitch) GetMeter(meterId uint32) *Meter {
	self.meterDbMux.Lock()
	defer self.meterDbMux.Unlock()
	return self.meterDb[meterId]
}

// Return a output graph element for the port
func (self *OFSwitch) OutputPort(portNo uint32) (*Output, error) {
	self.portMux.Lock()
	defer self.portMux.Unlock()

	if val, ok := self.outputPorts[portNo]; ok {
		return val, nil
	}

	// Create a new output element
	output := new(Output)
	output.outputType = "port"
	output.portNo = portNo

	// store all outputs in a DB
	self.outputPorts[portNo] = output

	return output, nil
}

// Return the drop graph element
func (self *OFSwitch) DropAction() *Output {
	return self.dropAction
}

// SendToController Return send to controller graph element
func (self *OFSwitch) SendToController() *Output {
	return self.sendToCtrler
}

// NormalLookup Return normal lookup graph element
func (self *OFSwitch) NormalLookup() *Output {
	return self.normalLookup
}

// FIXME: Unique group id for the flood entries
var uniqueGroupId uint32 = 1

// Create a new flood list
func (self *OFSwitch) NewFlood() (*Flood, error) {
	flood := new(Flood)

	flood.Switch = self
	flood.GroupId = uniqueGroupId
	uniqueGroupId += 1

	// Install it in HW right away
	flood.install()

	return flood, nil
}

// clearGroups clears all existing groups.
func (self *OFSwitch) clearGroups() error {
	groupMod := openflow15.NewGroupMod()
	groupMod.GroupId = openflow15.OFPG_ALL
	groupMod.Command = openflow15.OFPGC_DELETE
	groupMod.Type = openflow15.GT_ALL
	return self.Send(groupMod)
}
