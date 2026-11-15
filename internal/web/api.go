package web

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeError sends the standard error body. Messages are written for people and never contain
// internals, stack traces, SQL or secrets.
func writeError(w http.ResponseWriter, status int, code, message string) {
	var e apiError
	e.Error.Code, e.Error.Message = code, message
	writeJSON(w, status, e)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func typeName(v any) string { return fmt.Sprintf("%T", v) }

// allow answers 405 with an Allow header (as JSON, like every API error) unless the method is one of
// the allowed ones. It returns true when the handler should continue.
func allow(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", joinMethods(methods))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "This method is not allowed here.")
	return false
}

func joinMethods(ms []string) string {
	out := ""
	for i, m := range ms {
		if i > 0 {
			out += ", "
		}
		out += m
	}
	return out
}

// health is the only unauthenticated API route. It reveals nothing: no version, no uptime, no
// configuration, no database state. It exists so a supervisor or reverse proxy can tell the process
// is alive.
func health(w http.ResponseWriter, r *http.Request) {
	if !allow(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// apiNotFound handles every /api/ path nothing else claimed. It must never fall through to the UI's
// index.html, or a mistyped API call would return HTML with status 200.
func apiNotFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not_found", "No such API endpoint.")
}
