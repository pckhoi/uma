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
		map[string]types.UMAResouce{
			"/users": {
				Type:         "users",
				NameTemplate: "Users",
			},
			"/users/{id}": {
				Type:         "user",
				NameTemplate: "User {id}",
			},
		},
	))
	assert.Equal(t, strings.Join([]string{
		`package mypackage`,
		``,
		`import (`,
		`	"net/http"`,
		``,
		`	"github.com/pckhoi/uma"`,
		`)`,
		``,
		`var umaResourceTypes = map[string]uma.ResourceType{`,
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
		`var resourceTemplates = ResourceTemplates{`,
		`	uma.NewResourceTemplate("/users", "users", "Users"),`,
		``,
		`	uma.NewResourceTemplate("/users/{id}", "user", "User {id}"),`,
		`}`,
		``,
		`// UMAResourceMiddleware detects uma.Resource to be used in subsequent requests`,
		`func UMAResourceMiddleware(getBaseURL uma.BaseURLGetter) func(next http.Handler) http.Handler {`,
		`	return uma.UMAResouceMiddleware(getBaseURL, umaResourceTypes, resourceTemplates)`,
		`}`,
		``,
	}, "\n"), buf.String())
}
