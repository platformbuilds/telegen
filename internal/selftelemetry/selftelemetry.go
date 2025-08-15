package selftelemetry

import "net/http"

func StartServer() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	http.ListenAndServe(":19090", nil)
}
