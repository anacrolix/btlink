package main

import (
	"embed"
	"html/template"
)

//go:embed templates
var templatesFS embed.FS

var htmlTemplates = template.Must(
	template.New("").Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	}).ParseFS(templatesFS, "templates/*"))
