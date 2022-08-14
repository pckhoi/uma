package uma_test

import (
	"sort"
	"testing"

	"github.com/pckhoi/uma"
	"github.com/stretchr/testify/assert"
)

func TestResourceTemplate(t *testing.T) {
	types := map[string]uma.ResourceType{
		"user": {
			Type:           "user",
			Description:    "A user",
			IconUri:        "https://example.com/rsrcs/user.png",
			ResourceScopes: []string{"read", "write"},
		},
		"users": {
			Type:           "users",
			Description:    "A list of users",
			IconUri:        "https://example.com/rsrcs/users.png",
			ResourceScopes: []string{"list"},
		},
	}
	baseURL := "https://example.com/api"

	usersTmpl := uma.NewResourceTemplate("/users", "users", "Users")
	assert.Nil(t, usersTmpl.Match(types, baseURL, "/abc"))
	assert.Equal(t, &uma.Resource{
		ResourceType: types["users"],
		Name:         "Users",
		URI:          baseURL + "/users",
	}, usersTmpl.Match(types, baseURL, "/users"))

	userTmpl := uma.NewResourceTemplate("/users/{id}", "user", "User {id}")
	assert.Equal(t, &uma.Resource{
		ResourceType: types["user"],
		Name:         "User 123",
		URI:          baseURL + "/users/123",
	}, userTmpl.Match(types, baseURL, "/users/123"))
}

func TestResourceTemplates(t *testing.T) {
	var sl = uma.ResourceTemplates{
		uma.NewResourceTemplate("/config", "config", "Configuration"),
		uma.NewResourceTemplate("/users", "users", "Users"),
		uma.NewResourceTemplate("/users/{id}", "user", "User {id}"),
		uma.NewResourceTemplate("", "base", "Base"),
	}
	sort.Sort(sl)
	assert.Equal(t, uma.ResourceTemplates{
		uma.NewResourceTemplate("", "base", "Base"),
		uma.NewResourceTemplate("/config", "config", "Configuration"),
		uma.NewResourceTemplate("/users", "users", "Users"),
		uma.NewResourceTemplate("/users/{id}", "user", "User {id}"),
	}, sl)
}
