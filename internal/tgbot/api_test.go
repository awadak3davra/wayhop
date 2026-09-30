package tgbot

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetMeDecodesTheBot(t *testing.T) {
	f := newFakeAPI(t)
	f.on("getMe", func(map[string]any) (int, string) {
		return 200, `{"ok":true,"result":{"id":42,"is_bot":true,"first_name":"Home router","username":"home_wayhop_bot"}}`
	})
	u, err := f.client().GetMe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != 42 || u.Username != "home_wayhop_bot" || !u.IsBot {
		t.Fatalf("got %+v", u)
	}
}

func TestAPIErrorCarriesTelegramsWordsAndFloodWait(t *testing.T) {
	f := newFakeAPI(t)
	f.on("sendMessage", func(map[string]any) (int, string) {
		return 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`
	})
	_, err := f.client().SendMessage(context.Background(), 1, "hi", SendOptions{})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("want *APIError, got %T %v", err, err)
	}
	if ae.Code != 429 || ae.RetryAfter != 7 || retryAfter(err) != 7*time.Second {
		t.Fatalf("got %+v", ae)
	}
	if !strings.Contains(err.Error(), "retry after 7s") {
		t.Fatalf("message %q", err)
	}
}

func TestUnauthorizedAndConflictAreRecognised(t *testing.T) {
	f := newFakeAPI(t)
	f.on("getMe", func(map[string]any) (int, string) {
		return 401, `{"ok":false,"error_code":401,"description":"Unauthorized"}`
	})
	f.on("getUpdates", func(map[string]any) (int, string) {
		return 409, `{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`
	})
	c := f.client()
	if _, err := c.GetMe(context.Background()); !IsUnauthorized(err) {
		t.Fatalf("getMe: %v", err)
	}
	if _, err := c.GetUpdates(context.Background(), 0, 0); !IsConflict(err) {
		t.Fatalf("getUpdates: %v", err)
	}
}

// A block page or captive portal answers with HTML. The error must say what came back rather than
// "invalid character '<'", which sends people looking for a JSON bug.
func TestNonBotAPIResponseIsDescribed(t *testing.T) {
	f := newFakeAPI(t)
	f.on("getMe", func(map[string]any) (int, string) {
		return 403, "<html><body>Access denied by your provider</body></html>"
	})
	_, err := f.client().GetMe(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 403 || !strings.Contains(ae.Description, "Forbidden") {
		t.Fatalf("got %v", err)
	}
	if !IsBlocked(err) {
		t.Fatal("a 403 is a blocked chat for the send path")
	}
}

// The token is the bot's only credential and the request URL carries it. A transport error prints
// the URL; it must never reach the log with the token in it.
func TestTransportErrorNeverLeaksTheToken(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", testToken, &http.Client{Timeout: 2 * time.Second})
	_, err := c.GetMe(context.Background())
	if err == nil {
		t.Fatal("expected a dial error")
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "TEST-token") {
		t.Fatalf("token leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "<token>") {
		t.Fatalf("expected the scrubbed marker, got %v", err)
	}
}

func TestSendMessageShapesTheRequest(t *testing.T) {
	f := newFakeAPI(t)
	kb := &Keyboard{Rows: [][]InlineButton{{{Text: "Refresh", CallbackData: "st"}}}}
	m, err := f.client().SendMessage(context.Background(), 77, "<b>ok</b>", SendOptions{Keyboard: kb, Silent: true, ReplyTo: 5, NoPreview: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.Chat.ID != 77 || m.MessageID == 0 {
		t.Fatalf("result %+v", m)
	}
	p := f.callsTo("sendMessage")[0].Params
	if p["parse_mode"] != "HTML" || p["disable_notification"] != true || p["text"] != "<b>ok</b>" {
		t.Fatalf("params %v", p)
	}
	if rp, _ := p["reply_parameters"].(map[string]any); rp["message_id"] != float64(5) || rp["allow_sending_without_reply"] != true {
		t.Fatalf("reply_parameters %v", p["reply_parameters"])
	}
	rows := p["reply_markup"].(map[string]any)["inline_keyboard"].([]any)
	if btn := rows[0].([]any)[0].(map[string]any); btn["callback_data"] != "st" {
		t.Fatalf("keyboard %v", rows)
	}
}

func TestEditMessageTreatsNotModifiedAsSuccess(t *testing.T) {
	f := newFakeAPI(t)
	f.on("editMessageText", func(map[string]any) (int, string) {
		return 400, `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same"}`
	})
	if err := f.client().EditMessage(context.Background(), 1, 2, "same", nil); err != nil {
		t.Fatalf("a double Refresh is not an error: %v", err)
	}
}

func TestSendDocumentIsMultipart(t *testing.T) {
	f := newFakeAPI(t)
	if _, err := f.client().SendDocument(context.Background(), 9, "backup.json", []byte(`{"a":1}`), "<b>backup</b>"); err != nil {
		t.Fatal(err)
	}
	c := f.callsTo("sendDocument")[0]
	if !strings.HasPrefix(c.CT, "multipart/form-data") {
		t.Fatalf("content type %q", c.CT)
	}
	body := string(c.Raw)
	for _, want := range []string{`name="chat_id"`, "\r\n9\r\n", `filename="backup.json"`, `{"a":1}`, `name="parse_mode"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body lacks %q:\n%s", want, body)
		}
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	f := newFakeAPI(t)
	big := `{"ok":true,"result":"` + strings.Repeat("x", maxResponseBytes) + `"}`
	f.on("getMe", func(map[string]any) (int, string) { return 200, big })
	if _, err := f.client().GetMe(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestDisplayNames(t *testing.T) {
	if got := (User{ID: 1, FirstName: "Sam", LastName: "S"}).DisplayName(); got != "Sam S" {
		t.Fatal(got)
	}
	if got := (User{ID: 1, Username: "sam_s"}).DisplayName(); got != "@sam_s" {
		t.Fatal(got)
	}
	if got := (User{ID: 12}).DisplayName(); got != "12" {
		t.Fatal(got)
	}
	if got := (Chat{ID: -5, Type: "group", Title: "Family"}).DisplayName(); got != "Family" {
		t.Fatal(got)
	}
}
