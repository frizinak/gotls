package simplehttp

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

// HandleFunc will handle requests.
// Returning a status code will return an HTTP <status> to the user
// with the corresponding error message.
// Returning an error will result in an HTTP 500: internal server error
// and the error being logged.
// Writing to the httpResponseWriter is mutually exclusive with returning anything
// other than 0, nil
type HandleFunc func(w http.ResponseWriter, r *http.Request, l *log.Logger) (errStatus int, err error)

// Router decides which handleFunc should handle the given http.Request.
// Returning no handler: 404.
type Router func(r *http.Request, l *log.Logger) (handler HandleFunc)

// HTTPErrorHandler can write to an http.ResponseWriter
type HTTPErrorHandler interface {
	WriteTo(w http.ResponseWriter)
	GetHeaders() map[string]string
}

// HTTPError is a static HTTPErrorHandler implementation
type HTTPError struct {
	headers map[string]string
	content []byte
}

// GetHeaders returns the headers
func (h *HTTPError) GetHeaders() map[string]string {
	return h.headers
}

// WriteTo the given http.ResponseWriter
func (h *HTTPError) WriteTo(w http.ResponseWriter) {
	w.Write(h.content)
}

// NewHTTPError returns an HTTPError instance
func NewHTTPError(contentType string, content []byte) *HTTPError {
	return &HTTPError{map[string]string{"Content-Type": contentType}, content}
}

// Server is a tiny wrapper around an http.Server{}
type Server struct {
	s           *http.Server
	log         *log.Logger
	router      Router
	httpErrors  map[int]HTTPErrorHandler
	headers     map[string]string
	gzipEnabled bool
}

// New returns a new Server with the given router.
func New(router Router, logger *log.Logger) *Server {
	return FromHTTPServer(&http.Server{}, router, logger)
}

// FromHTTPServer converts an http.Server into a Server using the given router.
func FromHTTPServer(
	server *http.Server,
	router Router,
	logger *log.Logger,
) *Server {
	mux := http.NewServeMux()
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}

	s := &Server{
		router:      router,
		log:         logger,
		httpErrors:  make(map[int]HTTPErrorHandler),
		headers:     make(map[string]string),
		gzipEnabled: true,
	}

	mux.HandleFunc("/", s.reqHandler)
	s.s = server
	s.s.Handler = mux
	if s.s.ErrorLog == nil {
		s.s.ErrorLog = logger
	}

	return s
}

// OverrideMux sets a new mux on the underlying http server.
// Make sure to call one of the returned handlers
func (s *Server) OverrideMux(mux http.Handler) (stdlib, direct http.Handler) {
	stdlib = s.s.Handler
	direct = http.HandlerFunc(s.reqHandler)
	s.s.Handler = mux

	return
}

// SetHeader adds a header to all future reponses.
// Not thread safe.
func (s *Server) SetHeader(name string, value string) {
	s.headers[name] = value
}

// DisableGzip disables content gzipping.
func (s *Server) DisableGzip() {
	s.gzipEnabled = false
}

// RemoveHeader removes a header from all future reponses.
// Not thread safe.
func (s *Server) RemoveHeader(name string) {
	delete(s.headers, name)
}

// Start listening on the given address
func (s *Server) Start(addr interface{}, tls bool) error {
	switch a := addr.(type) {
	case string:
		s.s.Addr = a
		if tls {
			return s.s.ListenAndServeTLS("", "")
		}

		return s.s.ListenAndServe()
	case net.Listener:
		if tls {
			return s.s.ServeTLS(a, "", "")
		}

		return s.s.Serve(a)
	}

	return errors.New("Invalid addr type")
}

// SetHTTPErrorHandler adds or overrides an http error handler.
// Not thread safe.
func (s *Server) SetHTTPErrorHandler(status int, handler HTTPErrorHandler) {
	s.httpErrors[status] = handler
}

func (s *Server) reqHandler(w http.ResponseWriter, r *http.Request) {
	handler := s.router(r, s.log)
	if handler == nil {
		s.serveError(w, http.StatusNotFound, nil)
		return
	}

	s.handleRequest(w, r, handler)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request, cb HandleFunc) {
	if s.gzipEnabled {
		gz := &GZIPWriter{ResponseWriter: w, r: r}
		defer gz.Close()
		w = gz
	}

	headers := w.Header()
	for name, value := range s.headers {
		headers.Set(name, value)
	}

	status, err := cb(w, r, s.log)
	if status != 0 {
		s.serveError(w, status, err)
		return
	}

	if err != nil {
		s.serveError(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) serveError(w http.ResponseWriter, which int, err error) {
	if err != nil {
		s.log.Printf("%v", err)
	}

	headers := w.Header()
	headers.Set("Content-Type", "text/plain")

	if v, ok := s.httpErrors[which]; ok {
		for key, value := range v.GetHeaders() {
			headers.Set(key, value)
		}

		w.WriteHeader(which)
		v.WriteTo(w)
		return
	}

	if v := http.StatusText(which); v != "" {
		w.WriteHeader(which)
		w.Write([]byte(v))
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
}
