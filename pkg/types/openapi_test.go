package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const yamlStr = `
paths:
  x-uma-resource:
    type: https://example.co/rsrcs/users
    name: Users
  /users:
    get: {}
  /users/{id}:
    x-uma-resource:
      type: https://example.co/rsrcs/user
      name: "User {id}"
    get: {}
components:
  securitySchemes:
    oauth2:
      type: oauth2
      description: This API uses OAuth 2 with the authorization code flow.
      flows:
        authorizationCode:
        authorizationUrl: "https://as.example.com/authorize"
        tokenUrl: "https://as.example.com/token"
        scopes:
          read: Read data
          write: Write data
      list: List data
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
`
const jsonStr = `
{
	"paths": {
	  "x-uma-resource": {
		"type": "https://example.co/rsrcs/users",
		"name": "Users"
	  },
	  "/users": {
		"get": {}
	  },
	  "/users/{id}": {
		"x-uma-resource": {
		  "type": "https://example.co/rsrcs/user",
		  "name": "User {id}"
		},
		"get": {}
	  }
	},
	"components": {
	  "securitySchemes": {
		"oauth2": {
		  "type": "oauth2",
		  "description": "This API uses OAuth 2 with the authorization code flow.",
		  "flows": {
			"authorizationCode": null,
			"authorizationUrl": "https://as.example.com/authorize",
			"tokenUrl": "https://as.example.com/token",
			"scopes": {
			  "read": "Read data",
			  "write": "Write data",
			  "list": "List data"
			}
		  },
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
		  }
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
			Paths: &Paths{
				UMAResouce: &UMAResouce{
					Type:         "https://example.co/rsrcs/users",
					NameTemplate: "Users",
				},
				Paths: map[string]Path{
					"/users": {},
					"/users/{id}": {
						UMAResouce: &UMAResouce{
							Type:         "https://example.co/rsrcs/user",
							NameTemplate: "User {id}",
						},
					},
				},
			},
			Components: &Components{
				SecuritySchemes: map[string]SecurityScheme{
					"oauth2": {
						Type: "oauth2",
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
					},
				},
			},
		})
	}
}
