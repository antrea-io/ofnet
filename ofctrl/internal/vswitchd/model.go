package vswitchd

import (
	"github.com/ovn-org/libovsdb/model"
)

func Model() (model.ClientDBModel, error) {
	return model.NewClientDBModel("Open_vSwitch", map[string]model.Model{
		"Bridge":       &Bridge{},
		"Open_vSwitch": &OpenvSwitch{},
	})
}
