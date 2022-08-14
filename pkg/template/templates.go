package template

import (
	"bytes"
	"embed"
	"go/format"
	"io"
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

type middlewareCode struct {
	Package            string
	ResourceTypes      map[string]types.UMAResourceType
	ResourceTypeAtPath map[string]types.UMAResouce
}

func RenderMiddlewareCode(wr io.Writer, pkg string, types map[string]types.UMAResourceType, paths map[string]types.UMAResouce) error {
	buf := bytes.NewBuffer(nil)
	if err := tmpl.ExecuteTemplate(buf, "middleware.go.tmpl", middlewareCode{
		Package:            pkg,
		ResourceTypes:      types,
		ResourceTypeAtPath: paths,
	}); err != nil {
		return err
	}
	b, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}
	_, err = wr.Write(b)
	return err
}
