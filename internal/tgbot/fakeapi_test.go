package tgbot

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testToken = "123456:TEST-token_abcdefghijklmnopqrstuvwxyz"

// apiCall is one request the fake Bot API received.
type apiCall struct {
	Method string
	Params map[string]any
	Raw    []byte
	CT     string
}

// fakeAPI is an in-process Bot API. Handlers default to {"ok":true,"result":true}; a test overrides
// a method with on(). Every call is recorded in order.
type fakeAPI struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	calls []apiCall
	hs    map[string]func(p map[string]any) (int, string)
	msgID int64
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, hs: map[string]func(map[string]any) (int, string){}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client() *Client { return NewClient(f.srv.URL, testToken, f.srv.Client()) }

func (f *fakeAPI) on(method string, h func(p map[string]any) (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hs[method] = h
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	prefix := "/bot" + testToken + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":404,"description":"Not Found"}`)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, prefix)
	raw, _ := io.ReadAll(r.Body)
	p := map[string]any{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(raw, &p)
	}
	f.mu.Lock()
	f.calls = append(f.calls, apiCall{Method: method, Params: p, Raw: raw, CT: r.Header.Get("Content-Type")})
	h := f.hs[method]
	f.msgID++
	id := f.msgID
	f.mu.Unlock()
	if h != nil {
		code, body := h(p)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
		return
	}
	switch method {
	case "sendMessage", "sendDocument":
		chat, _ := p["chat_id"].(float64)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{
			"message_id": id, "chat": map[string]any{"id": int64(chat), "type": "private"}, "date": 1}})
	case "getUpdates":
		_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
	default:
		_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
	}
}

// lastKeyboard is the inline keyboard of the last call to method.
func (f *fakeAPI) lastKeyboard(t *testing.T, method string) [][]InlineButton {
	t.Helper()
	calls := f.callsTo(method)
	if len(calls) == 0 {
		t.Fatalf("no %s call", method)
	}
	var body struct {
		ReplyMarkup Keyboard `json:"reply_markup"`
	}
	if err := json.Unmarshal(calls[len(calls)-1].Raw, &body); err != nil {
		t.Fatal(err)
	}
	return body.ReplyMarkup.Rows
}

// callsTo returns the recorded calls of one method.
func (f *fakeAPI) callsTo(method string) []apiCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []apiCall
	for _, c := range f.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}
