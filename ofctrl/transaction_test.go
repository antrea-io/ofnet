package ofctrl

import (
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
)

func TestBundleReplyTimeout(t *testing.T) {
	testCases := []struct {
		name        string
		requestType uint16
		expected    error
	}{
		{
			name:        "open",
			requestType: openflow15.OFPBCT_OPEN_REQUEST,
			expected:    ErrBundleOpenReplyTimeout,
		},
		{
			name:        "close",
			requestType: openflow15.OFPBCT_CLOSE_REQUEST,
			expected:    ErrBundleCloseReplyTimeout,
		},
		{
			name:        "commit",
			requestType: openflow15.OFPBCT_COMMIT_REQUEST,
			expected:    ErrBundleCommitReplyTimeout,
		},
		{
			name:        "discard",
			requestType: openflow15.OFPBCT_DISCARD_REQUEST,
			expected:    ErrBundleDiscardReplyTimeout,
		},
		{
			name:        "unknown request",
			requestType: 0xffff,
			expected:    ErrBundleReplyTimeout,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := bundleReplyTimeout(tc.requestType)
			assert.ErrorIs(t, err, tc.expected)
			// Callers that only care that the outcome is unknown match the generic error.
			assert.ErrorIs(t, err, ErrBundleReplyTimeout)
			// A timeout must never be mistaken for a cancellation.
			assert.NotErrorIs(t, err, ErrBundleReplyCanceled)
		})
	}
}

func TestBundleReplyCanceled(t *testing.T) {
	testCases := []struct {
		name        string
		requestType uint16
		expected    error
	}{
		{
			name:        "open",
			requestType: openflow15.OFPBCT_OPEN_REQUEST,
			expected:    ErrBundleOpenReplyCanceled,
		},
		{
			name:        "close",
			requestType: openflow15.OFPBCT_CLOSE_REQUEST,
			expected:    ErrBundleCloseReplyCanceled,
		},
		{
			name:        "commit",
			requestType: openflow15.OFPBCT_COMMIT_REQUEST,
			expected:    ErrBundleCommitReplyCanceled,
		},
		{
			name:        "discard",
			requestType: openflow15.OFPBCT_DISCARD_REQUEST,
			expected:    ErrBundleDiscardReplyCanceled,
		},
		{
			name:        "unknown request",
			requestType: 0xffff,
			expected:    ErrBundleReplyCanceled,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := bundleReplyCanceled(tc.requestType)
			assert.ErrorIs(t, err, tc.expected)
			assert.ErrorIs(t, err, ErrBundleReplyCanceled)
			assert.NotErrorIs(t, err, ErrBundleReplyTimeout)
		})
	}
}

// TestBundleReplyErrorsAreDistinct checks that the error for one request type is not matched by
// another, so that a caller can tell a commit, whose outcome is unknown, from an open or close,
// which changed nothing.
func TestBundleReplyErrorsAreDistinct(t *testing.T) {
	assert.NotErrorIs(t, ErrBundleCommitReplyTimeout, ErrBundleOpenReplyTimeout)
	assert.NotErrorIs(t, ErrBundleCommitReplyCanceled, ErrBundleOpenReplyCanceled)
	assert.NotErrorIs(t, ErrBundleCommitReplyTimeout, ErrBundleCommitReplyCanceled)
}
