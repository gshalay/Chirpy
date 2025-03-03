package main

import "net/http"

func main() {
	mux := http.NewServeMux()
	httpServer := http.Server{Handler: mux, Addr: ":8080"}
	httpServer.ListenAndServe()
}
