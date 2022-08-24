package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const yamlStr = `
x-uma-resource-types:
  https://example.co/rsrcs/users:
    description: A list of users
    iconUri: https://example.co/rsrcs/users/icon.png
    resourceScopes:
      - list
  https://example.co/rsrcs/user:
    description: A user
    iconUri: https://example.co/rsrcs/user/icon.png
    resourceScopes:
      - read
      - write
x-uma-resource:
  type: https://example.co/rsrcs/users
  name: Users
paths:
  /users:
    get: 
      security:
        - oidc: [read]
  /users/{id}:
    x-uma-resource:
      type: https://example.co/rsrcs/user
      name: "User {id}"
    get:
      security:
        - oidc: [read]
components:
  securitySchemes:
    oidc:
      type: openIdConnect
      openIdConnectUrl: /.well-known/openid-configuration
      x-uma-enabled: true
`
const jsonStr = `
{
	"x-uma-resource-types": {
	  "https://example.co/rsrcs/users": {
		"description": "A list of users",
		"iconUri": "https://example.co/rsrcs/users/icon.png",
		"resourceScopes": ["list"]
	  },
	  "https://example.co/rsrcs/user": {
		"description": "A user",
		"iconUri": "https://example.co/rsrcs/user/icon.png",
		"resourceScopes": ["read", "write"]
	  }
	},
	"x-uma-resource": {
	  "type": "https://example.co/rsrcs/users",
	  "name": "Users"
	},
	"paths": {
	  "/users": {
		"get": {
			"security": [
				{"oidc": ["read"]}
			]
		}
	  },
	  "/users/{id}": {
		"x-uma-resource": {
		  "type": "https://example.co/rsrcs/user",
		  "name": "User {id}"
		},
		"get": {
			"security": [
				{"oidc": ["read"]}
			]
		}
	  }
	},
	"components": {
	  "securitySchemes": {
		"oidc": {
		  "type": "openIdConnect",
		  "openIdConnectUrl": "/.well-known/openid-configuration",
		  "x-uma-enabled": true
		}
	  }
	}
  }
`

func assertUnmarshalSpec(t *testing.T, filename, content string, spec *OpenAPISpec) {
	t.Helper()
	fpath := filepath.Join(t.TempDir(), filename)
	defer os.Remove(fpath)
	require.NoError(t, os.WriteFile(fpath, []byte(content), 0644))
	doc, err := OpenOpenAPISpec(fpath)
	require.NoError(t, err)
	assert.Equal(t, spec, doc)
}

func TestOpenAPISpect(t *testing.T) {
	for _, c := range []struct {
		Filename string
		Content  string
	}{
		{"oapi.yaml", yamlStr},
		{"oapi.json", jsonStr},
	} {
		assertUnmarshalSpec(t, c.Filename, c.Content, &OpenAPISpec{
			UMAResourceTypes: map[string]UMAResourceType{
				"https://example.co/rsrcs/user": {
					Description:    "A user",
					IconUri:        "https://example.co/rsrcs/user/icon.png",
					ResourceScopes: []string{"read", "write"},
				},
				"https://example.co/rsrcs/users": {
					Description:    "A list of users",
					IconUri:        "https://example.co/rsrcs/users/icon.png",
					ResourceScopes: []string{"list"},
				},
			},
			UMAResouce: &UMAResouce{
				Type:         "https://example.co/rsrcs/users",
				NameTemplate: "Users",
			},
			Paths: map[string]Path{
				"/users": {
					Get: &Operation{
						Security: []map[string][]string{
							{
								"oidc": {"read"},
							},
						},
					},
				},
				"/users/{id}": {
					UMAResouce: &UMAResouce{
						Type:         "https://example.co/rsrcs/user",
						NameTemplate: "User {id}",
					},
					Get: &Operation{
						Security: []map[string][]string{
							{
								"oidc": {"read"},
							},
						},
					},
				},
			},
			Components: &Components{
				SecuritySchemes: map[string]SecurityScheme{
					"oidc": {
						Type:       "openIdConnect",
						UMAEnabled: true,
					},
				},
			},
		})
	}
}
