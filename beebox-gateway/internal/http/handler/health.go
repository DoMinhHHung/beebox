package handler

import (
	"encoding/json"
	"net/http"
)

func Live(w http.ResponseWriter, _ *http.Request) {
	writeOK(w)
}

func Ready(w http.ResponseWriter, _ *http.Request) {
	writeOK(w)
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
