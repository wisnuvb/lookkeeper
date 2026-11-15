package web

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// uiHandler serves the single-page app: real files as they are, and every other extension-less path
// as index.html (the client-side router decides what to show). A missing file that LOOKS like a file
// (it has an extension) is a real 404, never index.html.
//
// Hard rules: only GET and HEAD; no dotfiles; paths are cleaned and confined to the embedded FS
// (fs.FS refuses ".." anyway); hashed build assets are cached for a year, everything else must be
// revalidated so a new version of the UI reaches users at once.
type uiHandler struct {
	fsys  fs.FS
	built bool
}

func (h uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.built {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "The web interface is not built into this binary.\nRun `make web-build web-embed build` and start the server again.\nThe API is available under /api/v1/.\n")
		return
	}

	clean := path.Clean("/" + r.URL.Path)
	name := strings.TrimPrefix(clean, "/")
	for _, seg := range strings.Split(name, "/") {
		if strings.HasPrefix(seg, ".") {
			http.NotFound(w, r)
			return
		}
	}
	if name == "" {
		name = "index.html"
	}

	st, err := fs.Stat(h.fsys, name)
	switch {
	case err == nil && !st.IsDir():
		// serve the file as it is
	case path.Ext(name) != "":
		http.NotFound(w, r) // looks like a file, is not there
		return
	default:
		name = "index.html" // a client-side route
	}

	f, err := h.fsys.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch {
	case name == "index.html":
		// The shell carries this response's CSP nonce. It differs on every response, so it must never be
		// stored or reused by a cache.
		data = bytes.ReplaceAll(data, []byte(noncePlaceholder), []byte(nonceFrom(r.Context())))
		w.Header().Set("Cache-Control", "no-store")
	case strings.HasPrefix(name, "assets/"):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data)) // Content-Type, Range and HEAD
}

// noncePlaceholder is what web/index.html contains in <meta name="csp-nonce" content="...">.
const noncePlaceholder = "__CSP_NONCE__"
