package template

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pckhoi/uma/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderMiddlewareCode(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	require.NoError(t, RenderMiddlewareCode(buf, "mypackage",
		map[string]types.UMAResourceType{
			"user": {
				Description:    "A user",
				IconUri:        "https://example.com/rsrcs/user.png",
				ResourceScopes: []string{"read", "write"},
			},
			"users": {
				Description:    "A list of users",
				IconUri:        "https://example.com/rsrcs/users.png",
				ResourceScopes: []string{"list"},
			},
		},
		map[string]string{
			"/users":      "users",
			"/users/{id}": "user",
		},
	))
	assert.Equal(t, strings.Join([]string{
		`package mypackage`,
		``,
		`import (`,
		`	"net/http"`,
		``,
		`	"github.com/pckhoi/uma/runtime"`,
		`)`,
		``,
		`var umaResourceTypes = map[string]runtime.UMAResourceType{`,
		`	"user": {`,
		`		Type:           "user",`,
		`		Description:    "A user",`,
		`		IconUri:        "https://example.com/rsrcs/user.png",`,
		`		ResourceScopes: []string{"read", "write"},`,
		`	},`,
		``,
		`	"users": {`,
		`		Type:           "users",`,
		`		Description:    "A list of users",`,
		`		IconUri:        "https://example.com/rsrcs/users.png",`,
		`		ResourceScopes: []string{"list"},`,
		`	},`,
		`}`,
		``,
		`var umaResourceTypeAtPath = map[string]string{`,
		`	"/users": "users",`,
		``,
		`	"/users/{id}": "user",`,
		`}`,
		``,
		`// UMAResourceMiddleware`,
		`func UMAResourceMiddleware(baseURL string) runtime.Middleware {`,
		`	return runtime.UMAResouceMiddleware(baseURL, umaResourceTypes, umaResourceTypeAtPath)`,
		`}`,
		``,
	}, "\n"), buf.String())
}
