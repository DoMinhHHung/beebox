package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	"Proxy-Connection",
}

func New(rawURL string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(req *http.Request) {
		original(req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.RequestURI = ""
		stripHopHeaders(req.Header)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		stripHopHeaders(resp.Header)
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		apperror.WriteJSON(w, apperror.New(apperror.CodeInternal, "upstream unavailable"))
	}
	return proxy, nil
}

func stripHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
	for _, v := range h.Values("Connection") {
		for _, hop := range strings.Split(v, ",") {
			if name := strings.TrimSpace(hop); name != "" {
				h.Del(name)
			}
		}
	}
}
