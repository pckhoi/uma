package testutil

import (
	"net/http"
	"testing"

	"github.com/dnaeon/go-vcr/v2/recorder"
	"github.com/stretchr/testify/require"
)

func RecordHTTP(t *testing.T, name string, update bool) (client *http.Client, stop func() error) {
	t.Helper()
	fixture := "testdata/go-vcr/" + name
	mode := recorder.ModeReplayingOrRecording
	if update {
		mode = recorder.ModeRecording
	}
	r, err := recorder.NewAsMode(fixture, mode, http.DefaultTransport)
	require.NoError(t, err)
	client = &http.Client{}
	*client = *http.DefaultClient
	client.Transport = r
	return client, r.Stop
}
