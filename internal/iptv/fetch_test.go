package iptv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchPlaylist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("fetch should send a User-Agent")
		}
		_, _ = w.Write([]byte("#EXTM3U url-tvg=\"http://epg\"\n#EXTINF:-1 tvg-id=\"a\",Alpha\nhttp://s/a\n"))
	}))
	defer srv.Close()
	pl, err := FetchPlaylist(context.Background(), srv.Client(), srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pl.URLTvg != "http://epg" || len(pl.Channels) != 1 || pl.Channels[0].Name != "Alpha" {
		t.Fatalf("parsed wrong: %+v", pl)
	}
}

func TestFetchPlaylistNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := FetchPlaylist(context.Background(), srv.Client(), srv.URL, 0); err == nil {
		t.Fatal("a 404 must be an error (so last-good is kept)")
	}
}

func TestFetchPlaylistNilClient(t *testing.T) {
	if _, err := FetchPlaylist(context.Background(), nil, "http://x", 0); err == nil {
		t.Fatal("nil client must error")
	}
}
