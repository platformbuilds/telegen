package selftelemetry

import (
	"log"
	"net/http"
)

func StartServer() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			return
		}
	})
	if err := http.ListenAndServe(":19090", nil); err != nil {
		log.Printf("selftelemetry server exited: %v", err)
	}
}
