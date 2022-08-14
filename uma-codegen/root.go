package main

import (
	"io"
	"os"

	"github.com/pckhoi/uma/pkg/template"
	"github.com/pckhoi/uma/pkg/types"
	"github.com/spf13/cobra"
)

func rootCmd() *cobra.Command {
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
			typesMap := map[string]types.UMAResourceType{}
			for _, ss := range doc.Components.SecuritySchemes {
				if ss.Type == "oauth2" && ss.UMAResourceTypes != nil {
					for k, v := range ss.UMAResourceTypes {
						typesMap[k] = v
					}
				}
			}
			paths := map[string]types.UMAResouce{}
			if doc.Paths.UMAResouce != nil {
				paths[""] = *doc.Paths.UMAResouce
			} else {
				for k, v := range doc.Paths.Paths {
					if v.UMAResouce != nil {
						paths[k] = *v.UMAResouce
					}
				}
			}
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
			return template.RenderMiddlewareCode(w, pkg, typesMap, paths)
		},
	}
	cmd.Flags().StringP("output", "o", "", "output generated code to this file")
	return cmd
}
