package middleware

import (
	"bytes"
	"net/http"

	"github.com/DoMinhHHung/beebox/libs/shared/apperror"
)

type bufferWriter struct {
	http.ResponseWriter
	hdr         http.Header
	buf         bytes.Buffer
	status      int
	wroteHeader bool
}

func (b *bufferWriter) Header() http.Header {
	if b.hdr == nil {
		b.hdr = make(http.Header)
	}
	return b.hdr
}

func (b *bufferWriter) WriteHeader(code int) {
	if b.wroteHeader {
		return
	}
	b.wroteHeader = true
	b.status = code
}

func (b *bufferWriter) Write(p []byte) (int, error) {
	if !b.wroteHeader {
		b.WriteHeader(http.StatusOK)
	}
	return b.buf.Write(p)
}

func (b *bufferWriter) flush() {
	dst := b.ResponseWriter.Header()
	for k, vs := range b.hdr {
		dst[k] = append([]string(nil), vs...)
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	b.ResponseWriter.WriteHeader(status)
	if b.buf.Len() > 0 {
		_, _ = b.ResponseWriter.Write(b.buf.Bytes())
	}
}

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bw := &bufferWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				apperror.WriteJSON(w, apperror.New(apperror.CodeInternal, "internal error"))
			}
		}()
		next.ServeHTTP(bw, r)
		bw.flush()
	})
}
