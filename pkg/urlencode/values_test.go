package urlencode

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

func TestToValues(t *testing.T) {
	type ClaimTokenFormat string

	const (
		AccessTokenFormat ClaimTokenFormat = "urn:ietf:params:oauth:token-type:jwt"
		IDTokenFormat     ClaimTokenFormat = "https://openid.net/specs/openid-connect-core-1_0.html#IDToken"
	)

	type Payload struct {
		StringField          string
		CustomStringField    ClaimTokenFormat
		ExplicitlyNamedField string `url:"explicit_field"`
		IgnoredField         string `url:"-"`
		unexportedField      string
		BoolField            bool
		IntField             int
		StringSliceField     []string
		BoolSliceField       []bool
		IntSliceField        []int
		StringPointer        *string
		IntPointer           *int
		BoolPointer          *bool
	}

	values, err := ToValues(&Payload{
		StringField:          "abc",
		CustomStringField:    AccessTokenFormat,
		ExplicitlyNamedField: "def",
		IgnoredField:         "qwe",
		unexportedField:      "asd",
		BoolField:            true,
		IntField:             10,
		StringSliceField:     []string{"a", "b"},
		BoolSliceField:       []bool{true, false},
		IntSliceField:        []int{1, 2},
		StringPointer:        strPtr(""),
		IntPointer:           intPtr(0),
		BoolPointer:          boolPtr(false),
	})
	require.NoError(t, err)
	assert.Equal(t, url.Values(map[string][]string{
		"bool_field":          {"true"},
		"bool_slice_field":    {"true", "false"},
		"custom_string_field": {string(AccessTokenFormat)},
		"explicit_field":      {"def"},
		"int_field":           {"10"},
		"int_slice_field":     {"1", "2"},
		"string_field":        {"abc"},
		"string_slice_field":  {"a", "b"},
		"string_pointer":      {""},
		"int_pointer":         {"0"},
		"bool_pointer":        {"false"},
	}), *values)

	values, err = ToValues(&Payload{
		StringField: "abc",
	})
	require.NoError(t, err)
	assert.Equal(t, url.Values(map[string][]string{
		"string_field": {"abc"},
	}), *values)
}
