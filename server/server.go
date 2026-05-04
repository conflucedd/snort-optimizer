package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"snort-optimizer/server/api"
	"snort-optimizer/server/store"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	var addr string
	var dbPath string
	var webDir string
	flag.StringVar(&addr, "addr", ":18080", "HTTP listen address")
	flag.StringVar(&dbPath, "db", filepath.Join(root, "server", "server.db"), "server sqlite database path")
	flag.StringVar(&webDir, "web-dir", filepath.Join(root, "web", "dist"), "built web directory")
	flag.Parse()

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	settings, err := st.GetSettings(root)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.EnsureRuntimeDirs(settings); err != nil {
		log.Fatal(err)
	}

	apiServer := api.New(root, st, log.New(os.Stderr, "server: ", log.LstdFlags))
	handler := mount(apiServer.Routes(), webDir)
	log.Printf("server listening on %s", displayAddr(addr))
	log.Fatal(http.ListenAndServe(addr, handler))
}

func mount(apiHandler http.Handler, webDir string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	fileServer := http.FileServer(http.Dir(webDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join(webDir, filepath.Clean(r.URL.Path))
		if stat, err := os.Stat(path); err == nil && !stat.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		index := filepath.Join(webDir, "index.html")
		if _, err := os.Stat(index); err == nil {
			http.ServeFile(w, r, index)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}
