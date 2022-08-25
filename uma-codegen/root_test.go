package main_test

import (
	"testing"

	main "github.com/pckhoi/uma/uma-codegen"
	"github.com/stretchr/testify/require"
)

func TestRootCmd(t *testing.T) {
	cmd := main.RootCmd()
	cmd.SetArgs([]string{"testdata/openapi.yml", "mypackage", "-o", "testdata/uma.gen.go"})
	require.NoError(t, cmd.Execute())
}
