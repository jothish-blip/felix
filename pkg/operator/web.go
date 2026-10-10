package operator

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var embeddedWebFS embed.FS

func (s *Server) handleWebStatic() http.Handler {
	subFS, err := fs.Sub(embeddedWebFS, "web")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(subFS))
}
