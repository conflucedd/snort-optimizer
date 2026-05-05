package main

import (
	"flag"
	"fmt"
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
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		log.Printf("Usage of %s:", os.Args[0])
		fs.VisitAll(func(f *flag.Flag) {
			log.Printf("  --%s\n\t%s", f.Name, f.Usage)
		})
	}
	fs.StringVar(&addr, "addr", ":18080", "HTTP listen address")
	fs.StringVar(&dbPath, "db", filepath.Join(root, "server.db"), "server sqlite database path")
	if err := rejectSingleDashArgs(os.Args[1:]); err != nil {
		log.Print(err)
		fs.Usage()
		os.Exit(2)
	}
	fs.Parse(os.Args[1:])

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
	webDir := filepath.Join(root, "web", "dist")
	handler := mount(apiServer.Routes(), webDir)
	log.Printf("server listening on %s", displayAddr(addr))
	log.Fatal(http.ListenAndServe(addr, handler))
}

func rejectSingleDashArgs(args []string) error {
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' && (len(arg) == 2 || arg[1] != '-') {
			return fmt.Errorf("single-dash argument %q is not supported; use --%s", arg, arg[1:])
		}
	}
	return nil
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
