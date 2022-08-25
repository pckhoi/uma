package main

import (
	"bytes"
	"embed"
	"go/format"
	"io"
	"regexp"
	"text/template"

	"github.com/pckhoi/uma/pkg/types"
)

//go:embed templates/*.tmpl
var templatesDir embed.FS

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.ParseFS(templatesDir, "templates/*.tmpl")
	if err != nil {
		panic(err)
	}
}

type resourceTemplate struct {
	Name string
	Type string
}

type operation struct {
	Security []map[string][]string
}

type path struct {
	Path         string
	ResourceType string
	ResourceName string
	Operations   map[string]operation
}

type middlewareTemplateData struct {
	Package                string
	ResourceTypes          map[string]types.UMAResourceType
	EnabledSecuritySchemes []string
	DefaultResource        *resourceTemplate
	DefaultSecurity        []map[string][]string
	Paths                  []path
}

func renderMiddlewareCode(wr io.Writer, tmplData middlewareTemplateData) error {
	buf := bytes.NewBuffer(nil)
	if err := tmpl.ExecuteTemplate(buf, "middleware.go.tmpl", tmplData); err != nil {
		return err
	}
	re := regexp.MustCompile(",\n[ \t]*\n")
	b, err := format.Source(re.ReplaceAll(buf.Bytes(), []byte(",\n")))
	if err != nil {
		return err
	}
	_, err = wr.Write(b)
	return err
}
