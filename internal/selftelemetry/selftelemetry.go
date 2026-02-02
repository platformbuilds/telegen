package selftelemetry

import "net/http"

func StartServer() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	_ = http.ListenAndServe(":19090", nil)
}
