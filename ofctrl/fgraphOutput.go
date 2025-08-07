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

// This file implements the forwarding graph API for the output element

import (
	"antrea.io/libOpenflow/openflow15"
)

type Output struct {
	outputType string // Output type: "drop", "toController" or "port"
	portNo     uint32 // Output port number
}

// Fgraph element type for the output
func (o *Output) Type() string {
	return "output"
}

// instruction set for output element
func (o *Output) GetFlowInstr() openflow15.Instruction {
	outputInstr := openflow15.NewInstrApplyActions()

	switch o.outputType {
	case "drop":
		return nil
	case "toController":
		outputAct := openflow15.NewActionOutput(openflow15.P_CONTROLLER)
		// Dont buffer the packets being sent to controller
		outputAct.MaxLen = openflow15.OFPCML_NO_BUFFER
		outputInstr.AddAction(outputAct, false)
	case "normal":
		fallthrough
	case "inPort":
		fallthrough
	case "port":
		outputAct := openflow15.NewActionOutput(o.portNo)
		outputInstr.AddAction(outputAct, false)
	}

	return outputInstr
}

// Return an output action (Used by group mods)
func (o *Output) GetActionMessage() openflow15.Action {
	switch o.outputType {
	case "drop":
		return nil
	case "toController":
		outputAct := openflow15.NewActionOutput(openflow15.P_CONTROLLER)
		// Dont buffer the packets being sent to controller
		outputAct.MaxLen = openflow15.OFPCML_NO_BUFFER

		return outputAct
	case "normal":
		fallthrough
	case "inPort":
		fallthrough
	case "port":
		return openflow15.NewActionOutput(o.portNo)
	}

	return nil
}

func (o *Output) GetActionType() string {
	return ActTypeOutput
}

func NewOutputInPort() *Output {
	return &Output{outputType: "inPort", portNo: openflow15.P_IN_PORT}
}

func NewOutputNormal() *Output {
	return &Output{outputType: "normal", portNo: openflow15.P_NORMAL}
}

func NewOutputPort(portNo uint32) *Output {
	return &Output{outputType: "port", portNo: portNo}
}

func NewOutputController() *Output {
	return &Output{outputType: "toController"}
}
