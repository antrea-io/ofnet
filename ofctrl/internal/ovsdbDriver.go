package internal

import (
	"context"
	"fmt"

	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	log "github.com/sirupsen/logrus"

	"antrea.io/ofnet/ofctrl/internal/vswitchd"
)

// OVS driver state
type OvsDriver struct {
	// OVS client
	client client.Client

	// Name of the OVS bridge
	brName string

	rootUUID string
}

func newOvsDriver(ctx context.Context, bridgeName string) (*OvsDriver, error) {
	dbModel, err := vswitchd.Model()
	if err != nil {
		return nil, err
	}
	ovs, err := client.NewOVSDBClient(dbModel, client.WithEndpoint("tcp:localhost:6640"))
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	if err := ovs.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to ovsdb: %w", err)
	}

	if _, err := ovs.Monitor(
		ctx,
		ovs.NewMonitor(
			client.WithTable(&vswitchd.OpenvSwitch{}),
			client.WithTable(&vswitchd.Bridge{}),
		),
	); err != nil {
		return nil, err
	}

	// Get root UUID
	var rootUUID string
	for uuid := range ovs.Cache().Table("Open_vSwitch").Rows() {
		rootUUID = uuid
	}

	ovsDriver := &OvsDriver{
		client:   ovs,
		brName:   bridgeName,
		rootUUID: rootUUID,
	}
	if err := ovsDriver.createBridge(ctx); err != nil {
		return nil, fmt.Errorf("failed to create bridge: %w", err)
	}
	return ovsDriver, nil
}

// Create a new OVS driver
func NewOvsDriver(bridgeName string) *OvsDriver {
	ovsDriver, err := newOvsDriver(context.Background(), bridgeName)
	if err != nil {
		log.Fatalf("fail to create OVS driver: %v", err)
	}
	return ovsDriver
}

// Delete removes the bridge and disconnects the client
func (d *OvsDriver) Delete() error {
	if d.client != nil {
		if err := d.deleteBridge(context.Background()); err != nil {
			return fmt.Errorf("error when deleting bridge %s: %w", d.brName, err)
		}
		log.Infof("Deleting OVS bridge: %s", d.brName)
		d.client.Disconnect()
	}

	return nil
}

// Wrapper for ovsDB transaction
func (d *OvsDriver) ovsdbTransact(ctx context.Context, ops []ovsdb.Operation) error {
	// Print out what we are sending
	log.Debugf("Transaction: %+v\n", ops)

	// Perform OVSDB transaction
	reply, err := d.client.Transact(ctx, ops...)
	if err != nil {
		return err
	}

	if _, err := ovsdb.CheckOperationResults(reply, ops); err != nil {
		return err
	}

	return nil
}

func (d *OvsDriver) createBridge(ctx context.Context) error {
	// If the bridge already exists, just return
	// FIXME: should we delete the old bridge and create new one?
	if _, ok := d.getBridgeUUID(); ok {
		return nil
	}

	const brNamedUUID = "testbr"

	protocols := []vswitchd.BridgeProtocols{
		vswitchd.BridgeProtocolsOpenflow10,
		vswitchd.BridgeProtocolsOpenflow11,
		vswitchd.BridgeProtocolsOpenflow12,
		vswitchd.BridgeProtocolsOpenflow13,
		vswitchd.BridgeProtocolsOpenflow14,
		vswitchd.BridgeProtocolsOpenflow15,
	}
	br := &vswitchd.Bridge{
		UUID:      brNamedUUID,
		FailMode:  &vswitchd.BridgeFailModeSecure,
		Name:      d.brName,
		Protocols: protocols,
	}

	insertOps, err := d.client.Create(br)
	if err != nil {
		return err
	}

	// Inserting/Deleting a Bridge row in Bridge table requires mutating
	// the open_vswitch table.
	ovsRow := vswitchd.OpenvSwitch{
		UUID: d.rootUUID,
	}
	mutateOps, err := d.client.Where(&ovsRow).Mutate(&ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: "insert",
		Value:   []string{br.UUID},
	})
	if err != nil {
		return err
	}

	ops := append(insertOps, mutateOps...)

	return d.ovsdbTransact(ctx, ops)
}

func (d *OvsDriver) deleteBridge(ctx context.Context) error {
	uuid, ok := d.getBridgeUUID()
	if !ok {
		return nil
	}
	br := &vswitchd.Bridge{
		UUID: uuid,
	}

	deleteOps, err := d.client.Where(br).Delete()
	if err != nil {
		return err
	}

	// Inserting/Deleting a Bridge row in Bridge table requires mutating
	// the open_vswitch table.
	ovsRow := vswitchd.OpenvSwitch{
		UUID: d.rootUUID,
	}
	mutateOps, err := d.client.Where(&ovsRow).Mutate(&ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: "delete",
		Value:   []string{br.UUID},
	})
	if err != nil {
		return err
	}

	ops := append(deleteOps, mutateOps...)

	return d.ovsdbTransact(ctx, ops)
}

func (d *OvsDriver) getBridgeUUID() (string, bool) {
	rows := d.client.Cache().Table("Bridge").Rows()
	for uuid, m := range rows {
		br := m.(*vswitchd.Bridge)
		if br.Name == d.brName {
			return uuid, true
		}
	}
	return "", false
}

func (d *OvsDriver) BridgeName() string {
	return d.brName
}
