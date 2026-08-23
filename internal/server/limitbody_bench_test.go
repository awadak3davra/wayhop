package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var benchHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func BenchmarkLimitBody_GET(b *testing.B) {
	wrapped := limitBody(benchHandler)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://test/api/health", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}
}

func BenchmarkLimitBodySkipSafe_GET(b *testing.B) {
	wrapped := limitBody(benchHandler)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://test/api/health", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}
}

func BenchmarkLimitBody_POST(b *testing.B) {
	wrapped := limitBody(benchHandler)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://test/api/endpoints", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}
}

func BenchmarkLimitBodySkipSafe_POST(b *testing.B) {
	wrapped := limitBody(benchHandler)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://test/api/endpoints", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}
}
