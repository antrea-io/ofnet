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

// This file implements the forwarding graph API for the Flood element

import (
	"errors"

	"antrea.io/libOpenflow/openflow15"

	log "github.com/sirupsen/logrus"
)

// Flood Fgraph element
type Flood struct {
	Switch      *OFSwitch // Switch where this flood entry is present
	GroupId     uint32    // Unique id for the openflow group
	isInstalled bool      // Is this installed in the datapath

	FloodList []FloodOutput // List of output ports to flood to
}

type FloodOutput struct {
	outPort  *Output
	isTunnel bool
	tunnelId uint64
}

// Fgraph element type for the output
func (f *Flood) Type() string {
	return "flood"
}

// instruction set for output element
func (f *Flood) GetFlowInstr() openflow15.Instruction {
	// If there are no ports in the flood entry, return
	if !f.isInstalled {
		return nil
	}

	groupInstr := openflow15.NewInstrApplyActions()
	groupAct := openflow15.NewActionGroup(f.GroupId)
	groupInstr.AddAction(groupAct, false)

	return groupInstr
}

// Add a new Output to group element
func (f *Flood) AddOutput(out *Output) error {
	f.FloodList = append(f.FloodList, FloodOutput{out, false, 0})

	// Install in the HW
	return f.install()
}

// Add a new Output to group element
func (f *Flood) AddTunnelOutput(out *Output, tunnelId uint64) error {
	f.FloodList = append(f.FloodList, FloodOutput{out, true, tunnelId})

	// Install in the HW
	return f.install()
}

// Remove a port from flood list
func (f *Flood) RemoveOutput(out *Output) error {
	// walk all flood list entries and see if it matches the output port
	for idx, output := range f.FloodList {
		if output.outPort == out {
			// Remove from the flood list. strange golang syntax to remove an element from slice
			f.FloodList = append(f.FloodList[:idx], f.FloodList[idx+1:]...)

			// Re-install the flood list with removed port
			return f.install()
		}
	}

	return errors.New("Output not found")
}

// Return number of ports in flood list
func (f *Flood) NumOutput() int {
	return len(f.FloodList)
}

// Install a group entry in OF switch
func (f *Flood) install() error {
	groupMod := openflow15.NewGroupMod()
	groupMod.GroupId = f.GroupId

	// Change the OP to modify if it was already installed
	if f.isInstalled {
		groupMod.Command = openflow15.OFPGC_MODIFY
	}

	// OF type for flood list
	groupMod.Type = openflow15.GT_ALL

	// Loop thru all output ports and add it to group bucket
	for idx, output := range f.FloodList {
		// Get the output action from output entry
		act := output.outPort.GetActionMessage()
		if act != nil {
			// Create a new bucket for each port
			bkt := openflow15.NewBucket(uint32(idx))

			// Set tunnel Id if required
			if output.isTunnel {
				tunnelField := openflow15.NewTunnelIdField(output.tunnelId)
				setTunnel := openflow15.NewActionSetField(*tunnelField)
				bkt.AddAction(setTunnel)
			}

			// Always remove vlan tag
			popVlan := openflow15.NewActionPopVlan()
			bkt.AddAction(popVlan)

			// Add the output action to the bucket
			bkt.AddAction(act)

			// Add the bucket to group
			groupMod.AddBucket(*bkt)
		}
	}

	log.Debugf("Installing Group entry: %+v", groupMod)

	// Send it to the switch
	if err := f.Switch.Send(groupMod); err != nil {
		return err
	}

	// Mark it as installed
	f.isInstalled = true

	return nil
}

// Delete a flood list
func (f *Flood) Delete() error {
	// Remove it from OVS if its installed
	if f.isInstalled {
		groupMod := openflow15.NewGroupMod()
		groupMod.GroupId = f.GroupId
		groupMod.Command = openflow15.OFPGC_DELETE

		log.Debugf("Deleting Group entry: %+v", groupMod)

		// Send it to the switch
		if err := f.Switch.Send(groupMod); err != nil {
			return err
		}
	}

	return nil
}
