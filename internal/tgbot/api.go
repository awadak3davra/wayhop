// Package tgbot is WayHop's Telegram bot: a small Bot API client, the long-poll loop, the command
// and button router, the message views and the alert queue. It depends on the standard library and
// on the Backend interface only, so every flow is testable without a router or a real bot.
//
// The daemon long-polls the Bot API outbound, which is why the bot works behind CGNAT and double
// NAT with no port forwarding - the same reason the rest of WayHop does not need one.
package tgbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIBase is the public Bot API. A self-hosted telegram-bot-api server or a reverse proxy can
// stand in for it where api.telegram.org is blocked.
const DefaultAPIBase = "https://api.telegram.org"

// maxResponseBytes caps a Bot API response. getUpdates with 100 updates of long messages stays far
// below this; anything bigger is not the Bot API talking.
const maxResponseBytes = 4 << 20

// Client calls the Bot API. It is safe for concurrent use.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// NewClient returns a client for token against base ("" means DefaultAPIBase). hc carries the
// transport (a tunnel-bound dialer, a proxy); nil means a plain client. Per-call deadlines come
// from the context, so hc should not set a Timeout that would cut a long poll short.
func NewClient(base, token string, hc *http.Client) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = DefaultAPIBase
	}
	if hc == nil {
		hc = &http.Client{}
	}
	return &Client{base: base, token: token, hc: hc}
}

// APIError is a Bot API refusal ({"ok":false,...}) or a non-JSON HTTP failure.
type APIError struct {
	Method      string
	Code        int    // error_code, or the HTTP status when the body was not the Bot API's
	Description string // Telegram's own words, e.g. "Bad Request: message is not modified"
	RetryAfter  int    // seconds to wait before retrying (429 flood control), 0 when not given
	MigrateTo   int64  // a group became a supergroup with this id, 0 when not given
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("telegram %s: %d %s (retry after %ds)", e.Method, e.Code, e.Description, e.RetryAfter)
	}
	return fmt.Sprintf("telegram %s: %d %s", e.Method, e.Code, e.Description)
}

// IsUnauthorized reports whether err is Telegram rejecting the token itself.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Code == http.StatusUnauthorized || ae.Code == http.StatusNotFound)
}

// IsConflict reports whether another getUpdates consumer (or a webhook) holds the bot.
func IsConflict(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == http.StatusConflict
}

// IsNotModified reports Telegram's refusal to edit a message into identical content - harmless for
// a Refresh button pressed twice.
func IsNotModified(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && strings.Contains(ae.Description, "message is not modified")
}

// IsBlocked reports that the chat can no longer be written to: the user blocked the bot, left the
// group, or the chat was deleted.
func IsBlocked(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == http.StatusForbidden
}

// migratedTo is the supergroup a refused send should go to instead: Telegram refuses a group that
// became a supergroup and names the new id. 0 when err is not that refusal.
func migratedTo(err error) int64 {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.MigrateTo
	}
	return 0
}

// retryAfter extracts the flood-control wait from err, 0 when there is none.
func retryAfter(err error) time.Duration {
	var ae *APIError
	if errors.As(err, &ae) && ae.RetryAfter > 0 {
		return time.Duration(ae.RetryAfter) * time.Second
	}
	return 0
}

type envelope struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  *struct {
		RetryAfter      int   `json:"retry_after"`
		MigrateToChatID int64 `json:"migrate_to_chat_id"`
	} `json:"parameters"`
}

// call POSTs params as JSON to method and decodes the result into out (nil to discard).
func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("telegram %s: encode: %w", method, err)
	}
	return c.do(ctx, method, "application/json", bytes.NewReader(body), out)
}

func (c *Client) do(ctx context.Context, method, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.token+"/"+method, body)
	if err != nil {
		return c.scrub(fmt.Errorf("telegram %s: %w", method, err))
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.hc.Do(req)
	if err != nil {
		// *url.Error prints the request URL, and the URL carries the token.
		return c.scrub(fmt.Errorf("telegram %s: %w", method, err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return c.scrub(fmt.Errorf("telegram %s: read: %w", method, err))
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("telegram %s: response larger than %d bytes", method, maxResponseBytes)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Not the Bot API: a captive portal, a block page, a proxy error. Say what came back.
		return &APIError{Method: method, Code: resp.StatusCode, Description: httpSummary(resp.StatusCode, raw)}
	}
	if !env.OK {
		ae := &APIError{Method: method, Code: env.ErrorCode, Description: env.Description}
		if ae.Code == 0 {
			ae.Code = resp.StatusCode
		}
		if env.Parameters != nil {
			ae.RetryAfter = env.Parameters.RetryAfter
			ae.MigrateTo = env.Parameters.MigrateToChatID
		}
		return ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("telegram %s: decode result: %w", method, err)
	}
	return nil
}

// scrub removes the token from err's text. The token is a bearer credential for the whole bot, and
// errors end up in the daemon log and in the panel.
func (c *Client) scrub(err error) error {
	if err == nil || c.token == "" || !strings.Contains(err.Error(), c.token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), c.token, "<token>"))
}

// httpSummary is a short, printable description of a non-Bot-API response.
func httpSummary(status int, raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	if s == "" {
		return http.StatusText(status)
	}
	return http.StatusText(status) + ": " + s
}

// User is a Telegram user or bot.
type User struct {
	ID           int64  `json:"id"`
	IsBot        bool   `json:"is_bot"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name,omitempty"`
	Username     string `json:"username,omitempty"`
	LanguageCode string `json:"language_code,omitempty"`
}

// DisplayName is the name a person would recognise: "First Last" or @username.
func (u User) DisplayName() string {
	n := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if n == "" && u.Username != "" {
		return "@" + u.Username
	}
	if n == "" {
		return strconv.FormatInt(u.ID, 10)
	}
	return n
}

// Chat is where a message lives.
type Chat struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"` // private | group | supergroup | channel
	Title     string `json:"title,omitempty"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// DisplayName is the chat's title, or its person's name for a private chat.
func (c Chat) DisplayName() string {
	if c.Title != "" {
		return c.Title
	}
	return User{ID: c.ID, FirstName: c.FirstName, LastName: c.LastName, Username: c.Username}.DisplayName()
}

// Message is the part of a Telegram message the bot reads.
type Message struct {
	MessageID int64  `json:"message_id"`
	From      *User  `json:"from,omitempty"`
	Chat      Chat   `json:"chat"`
	Date      int64  `json:"date"`
	Text      string `json:"text,omitempty"`
	// A group that became a supergroup is announced in both chats: the old one names the new id,
	// the new one the old.
	MigrateToChatID   int64 `json:"migrate_to_chat_id,omitempty"`
	MigrateFromChatID int64 `json:"migrate_from_chat_id,omitempty"`
}

// CallbackQuery is an inline-button press.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data,omitempty"`
}

// Update is one event from getUpdates.
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	ChannelPost   *Message       `json:"channel_post,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

// InlineButton is one inline-keyboard button: either callback data or a URL.
type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
	URL          string `json:"url,omitempty"`
}

// Keyboard is an inline keyboard: rows of buttons.
type Keyboard struct {
	Rows [][]InlineButton `json:"inline_keyboard"`
}

// SendOptions is how a message is sent. HTML parse mode is always used; views escape their text.
type SendOptions struct {
	Keyboard  *Keyboard
	Silent    bool  // disable_notification: arrives without a sound
	ReplyTo   int64 // reply to this message id (0 = no reply)
	NoPreview bool  // no link preview
	// Ask opens the reply field in the client with this placeholder, for a question the next
	// message answers (a force_reply markup; it replaces Keyboard).
	Ask string
}

type forceReply struct {
	ForceReply  bool   `json:"force_reply"`
	Placeholder string `json:"input_field_placeholder,omitempty"`
}

type linkPreview struct {
	IsDisabled bool `json:"is_disabled"`
}

type replyParams struct {
	MessageID                int64 `json:"message_id"`
	AllowSendingWithoutReply bool  `json:"allow_sending_without_reply"`
}

type sendMessageReq struct {
	ChatID              int64        `json:"chat_id"`
	Text                string       `json:"text"`
	ParseMode           string       `json:"parse_mode"`
	ReplyMarkup         any          `json:"reply_markup,omitempty"`
	DisableNotification bool         `json:"disable_notification,omitempty"`
	ReplyParameters     *replyParams `json:"reply_parameters,omitempty"`
	LinkPreviewOptions  *linkPreview `json:"link_preview_options,omitempty"`
}

// GetMe returns the bot's own identity; it is also the cheapest token check.
func (c *Client) GetMe(ctx context.Context) (User, error) {
	var u User
	err := c.call(ctx, "getMe", struct{}{}, &u)
	return u, err
}

// GetUpdates long-polls for updates after offset. timeout is the server-side hold in seconds; the
// caller's context must outlive it.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout int) ([]Update, error) {
	var ups []Update
	err := c.call(ctx, "getUpdates", map[string]any{
		"offset":          offset,
		"timeout":         timeout,
		"allowed_updates": []string{"message", "callback_query", "channel_post"},
	}, &ups)
	return ups, err
}

// SendMessage sends HTML text to chat and returns the sent message.
func (c *Client) SendMessage(ctx context.Context, chat int64, html string, o SendOptions) (Message, error) {
	req := sendMessageReq{ChatID: chat, Text: fit(html), ParseMode: "HTML", DisableNotification: o.Silent}
	switch {
	case o.Ask != "":
		req.ReplyMarkup = forceReply{ForceReply: true, Placeholder: o.Ask}
	case o.Keyboard != nil:
		req.ReplyMarkup = o.Keyboard
	}
	if o.ReplyTo != 0 {
		req.ReplyParameters = &replyParams{MessageID: o.ReplyTo, AllowSendingWithoutReply: true}
	}
	if o.NoPreview {
		req.LinkPreviewOptions = &linkPreview{IsDisabled: true}
	}
	var m Message
	err := c.call(ctx, "sendMessage", req, &m)
	return m, err
}

// EditMessage replaces a message's text and keyboard. A nil keyboard removes the buttons.
func (c *Client) EditMessage(ctx context.Context, chat, msg int64, html string, kb *Keyboard) error {
	req := map[string]any{
		"chat_id": chat, "message_id": msg, "text": fit(html), "parse_mode": "HTML",
		"link_preview_options": linkPreview{IsDisabled: true},
	}
	if kb != nil {
		req["reply_markup"] = kb
	}
	err := c.call(ctx, "editMessageText", req, nil)
	if IsNotModified(err) {
		return nil
	}
	return err
}

// AnswerCallback acknowledges a button press; text (optional) shows as a toast, alert=true as a
// modal the user has to dismiss.
func (c *Client) AnswerCallback(ctx context.Context, id, text string, alert bool) error {
	req := map[string]any{"callback_query_id": id}
	if text != "" {
		// Telegram takes 0-200 characters here and refuses the whole answer beyond that.
		if r := []rune(text); len(r) > maxAnswer {
			text = string(r[:maxAnswer-1]) + "…"
		}
		req["text"] = text
		req["show_alert"] = alert
	}
	return c.call(ctx, "answerCallbackQuery", req, nil)
}

// DeleteMessage deletes a message the bot sent.
func (c *Client) DeleteMessage(ctx context.Context, chat, msg int64) error {
	return c.call(ctx, "deleteMessage", map[string]any{"chat_id": chat, "message_id": msg}, nil)
}

// Command is one entry of the bot's command menu.
type Command struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// SetCommands publishes the command menu, for one language ("" = the default for everyone).
func (c *Client) SetCommands(ctx context.Context, cmds []Command, lang string) error {
	req := map[string]any{"commands": cmds}
	if lang != "" {
		req["language_code"] = lang
	}
	return c.call(ctx, "setMyCommands", req, nil)
}

// SetChatCommands publishes one chat's own command menu, which outranks the menus kept per client
// language; DeleteChatCommands takes it back, and the chat sees those again.
func (c *Client) SetChatCommands(ctx context.Context, chat int64, cmds []Command) error {
	return c.call(ctx, "setMyCommands", map[string]any{"commands": cmds, "scope": chatScope(chat)}, nil)
}

func (c *Client) DeleteChatCommands(ctx context.Context, chat int64) error {
	return c.call(ctx, "deleteMyCommands", map[string]any{"scope": chatScope(chat)}, nil)
}

func chatScope(chat int64) map[string]any { return map[string]any{"type": "chat", "chat_id": chat} }

// SetDescription sets what Telegram shows in an empty chat with the bot, before /start (at most 512
// characters); SetShortDescription the line on the bot's profile (at most 120). lang "" is the
// default for every client language without its own.
func (c *Client) SetDescription(ctx context.Context, text, lang string) error {
	req := map[string]any{"description": text}
	if lang != "" {
		req["language_code"] = lang
	}
	return c.call(ctx, "setMyDescription", req, nil)
}

func (c *Client) SetShortDescription(ctx context.Context, text, lang string) error {
	req := map[string]any{"short_description": text}
	if lang != "" {
		req["language_code"] = lang
	}
	return c.call(ctx, "setMyShortDescription", req, nil)
}

// DeleteWebhook drops a webhook left by another tool, which would otherwise make every getUpdates
// fail with 409 Conflict. Pending updates are kept.
func (c *Client) DeleteWebhook(ctx context.Context) error {
	return c.call(ctx, "deleteWebhook", map[string]any{"drop_pending_updates": false}, nil)
}

// SendDocument uploads data as a file named name, with an HTML caption.
func (c *Client) SendDocument(ctx context.Context, chat int64, name string, data []byte, caption string) (Message, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chat, 10))
	if caption != "" {
		_ = mw.WriteField("caption", caption)
		_ = mw.WriteField("parse_mode", "HTML")
	}
	fw, err := mw.CreateFormFile("document", name)
	if err != nil {
		return Message{}, fmt.Errorf("telegram sendDocument: %w", err)
	}
	if _, err := fw.Write(data); err != nil {
		return Message{}, fmt.Errorf("telegram sendDocument: %w", err)
	}
	if err := mw.Close(); err != nil {
		return Message{}, fmt.Errorf("telegram sendDocument: %w", err)
	}
	var m Message
	err = c.do(ctx, "sendDocument", mw.FormDataContentType(), &buf, &m)
	return m, err
}
