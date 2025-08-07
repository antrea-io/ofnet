// #nosec G404: random number generator not used for security purposes
package ofctrl

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/libOpenflow/openflow15"
)

type multipartActor struct {
	*OfActor
	expectedTxs map[uint32]chan *openflow15.MultipartReply
}

func (o *multipartActor) MultipartReply(sw *OFSwitch, rep *openflow15.MultipartReply) {
	if ch, found := o.expectedTxs[rep.Xid]; found {
		ch <- rep
	}
}
func TestMultipartReply(t *testing.T) {
	app := new(multipartActor)
	app.OfActor = new(OfActor)
	app.expectedTxs = make(map[uint32]chan *openflow15.MultipartReply)
	ctrl := NewController(app)
	brName := "brMultipart"
	ovsBr := prepareControllerAndSwitch(t, app.OfActor, ctrl, brName)
	defer func() {
		assert.Nilf(t, ovsBr.DeleteBridge(brName), "Failed to delete br %s", brName)
		ctrl.Delete()
	}()
	testTableFeatures(t, app)
}

func testTableFeatures(t *testing.T, app *multipartActor) {
	app.Switch.EnableMonitor()
	ofSwitch := app.Switch
	mpartRequest := &openflow15.MultipartRequest{
		Header: openflow15.NewOfp15Header(),
		Type:   openflow15.MultipartType_TableFeatures,
		Flags:  0,
	}
	mpartRequest.Header.Type = openflow15.Type_MultiPartRequest
	mpartRequest.Length = mpartRequest.Len()
	ch := make(chan *openflow15.MultipartReply)
	xid := mpartRequest.Xid
	app.expectedTxs[xid] = ch
	ofSwitch.Send(mpartRequest)

	getTableCount := func() int {
		tableCount := 0
		for rep := range ch {
			flags := rep.Flags
			tableLen := len(rep.Body)
			tableCount += tableLen
			if flags == 0 {
				break
			}
		}
		return tableCount
	}
	tableCount := getTableCount()
	assert.Equal(t, 254, tableCount)
	delete(app.expectedTxs, xid)
	close(ch)
}
