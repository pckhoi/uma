package main

import (
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/pckhoi/uma/pkg/types"
	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uma-codegen OPENAPI_DOC PACKAGE [-o OUTPUT]",
		Short: "Generate code based on UMA extension in OpenAPI spec",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oapiPath, pkg := args[0], args[1]
			output, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}
			doc, err := types.OpenOpenAPISpec(oapiPath)
			if err != nil {
				return err
			}

			var securitySchemes []string
			if doc.Components != nil {
				for name, ss := range doc.Components.SecuritySchemes {
					if ss.UMAEnabled {
						securitySchemes = append(securitySchemes, name)
					}
				}
			}

			var rsc *resourceTemplate
			if doc.UMAResouce != nil {
				rsc = &resourceTemplate{
					Name: doc.UMAResouce.NameTemplate,
					Type: doc.UMAResouce.Type,
				}
			}

			paths := []path{}
			for name, p := range doc.Paths {
				obj := path{
					Path:       name,
					Operations: map[string]operation{},
				}
				if p.UMAResouce != nil {
					obj.ResourceName = p.UMAResouce.NameTemplate
					obj.ResourceType = p.UMAResouce.Type
				}
				v := reflect.ValueOf(p)
				vt := v.Type()
				n := vt.NumField()
				for i := 0; i < n; i++ {
					sf := vt.FieldByIndex([]int{i})
					if sf.Type.Kind() == reflect.Pointer && strings.HasSuffix(sf.Type.Elem().Name(), "Operation") {
						f := v.FieldByIndex([]int{i})
						if f.IsZero() {
							continue
						}
						op := &operation{}
						sec := f.Elem().FieldByName("Security")
						if !sec.IsZero() {
							op.Security = make([]map[string][]string, sec.Len())
							reflect.Copy(reflect.ValueOf(op.Security), sec)
						}
						obj.Operations[strings.ToUpper(sf.Name)] = *op
					}
				}
				paths = append(paths, obj)
			}
			sort.Slice(paths, func(i, j int) bool {
				ni, nj := len(paths[i].Path), len(paths[j].Path)
				if ni > nj {
					return false
				} else if ni < nj {
					return true
				}
				return paths[i].Path < paths[j].Path
			})

			var w io.Writer
			if output == "" {
				w = cmd.OutOrStdout()
			} else {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return renderMiddlewareCode(w, middlewareTemplateData{
				Package:                pkg,
				EnabledSecuritySchemes: securitySchemes,
				ResourceTypes:          doc.UMAResourceTypes,
				DefaultResource:        rsc,
				DefaultSecurity:        doc.Security,
				Paths:                  paths,
			})
		},
	}
	cmd.Flags().StringP("output", "o", "", "output generated code to this file")
	return cmd
}
