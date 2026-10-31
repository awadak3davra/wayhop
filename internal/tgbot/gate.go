package tgbot

import (
	"crypto/rand"
	"crypto/subtle"
	"sort"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
)

// Roles a paired chat can have. See config.TelegramChat.
const (
	roleOwner  = config.TelegramOwner
	roleViewer = config.TelegramViewer
	roleAlerts = config.TelegramAlerts
)

const (
	// codeAlphabet has no 0/O or 1/I/L: the code is read off a screen and typed on a phone.
	codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	codeLen      = 8
	// CodeTTL is how long a pairing code stays valid.
	CodeTTL = 10 * time.Minute
	// maxBadCodes wrong codes per chat per badCodeWindow lock that chat out of pairing. At most
	// maxBadChats chats are remembered; the one whose last wrong code is oldest goes first.
	maxBadCodes   = 5
	badCodeWindow = time.Hour
	maxBadChats   = 256
	// strangerTTL is how long a chat that wrote to the bot unpaired stays listed in the panel.
	strangerTTL  = 24 * time.Hour
	maxStrangers = 20
	// refuseEvery limits the refusal reply to one per chat per this interval.
	refuseEvery = 10 * time.Minute
)

// Gate decides who may talk to the bot: one-time pairing codes, a wrong-code limit, and the list
// of chats that tried without one (so the panel can let them in). It outlives any one Bot, so a
// code issued before a settings change still works after the bot restarts.
type Gate struct {
	mu        sync.Mutex
	now       func() time.Time
	codes     map[string]pending
	bad       map[int64][]time.Time
	strangers map[int64]*Stranger
	// limitTold is when each chat locked out of pairing was last told so. Only chats in bad are kept,
	// so it is bounded the same way.
	limitTold map[int64]time.Time
}

type pending struct {
	role string
	exp  time.Time
}

// Stranger is a chat that wrote to the bot without being paired.
type Stranger struct {
	ChatID    int64     `json:"chat_id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Username  string    `json:"username,omitempty"`
	Lang      string    `json:"lang,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Attempts  int       `json:"attempts"`
	refusedAt time.Time
}

// NewGate returns an empty gate.
func NewGate() *Gate {
	return &Gate{now: time.Now, codes: map[string]pending{}, bad: map[int64][]time.Time{}, strangers: map[int64]*Stranger{},
		limitTold: map[int64]time.Time{}}
}

// NewCode issues a single-use pairing code for role. Codes for owner pair only private chats (see
// Redeem); a group paired with an owner code becomes a viewer. A role not named, or not known, gives
// the least that can still talk to the bot: a viewer. It used to give an owner, the role that can
// apply, restart and download every secret, to whoever redeemed a code issued without one.
func (g *Gate) NewCode(role string) (string, time.Time) {
	switch role {
	case roleOwner, roleViewer, roleAlerts:
	default:
		role = roleViewer
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expireLocked()
	code := randomCode()
	exp := g.now().Add(CodeTTL)
	g.codes[code] = pending{role: role, exp: exp}
	return code, exp
}

func randomCode() string {
	buf := make([]byte, codeLen)
	if _, err := rand.Read(buf); err != nil {
		panic("tgbot: crypto/rand failed: " + err.Error())
	}
	out := make([]byte, codeLen)
	for i, b := range buf {
		// 256 is not a multiple of 31; the bias is < 1% per character and irrelevant for a
		// 10-minute single-use code guarded by a five-attempt limit.
		out[i] = codeAlphabet[int(b)%len(codeAlphabet)]
	}
	return string(out)
}

// normalizeCode accepts what a person types: any case, spaces or dashes in between.
func normalizeCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	return strings.NewReplacer(" ", "", "-", "").Replace(s)
}

// looksLikeCode reports whether text typed on its own is plausibly a pairing code, so "hello" to
// an unpaired bot gets the explanation rather than "wrong code" and a spent attempt.
func looksLikeCode(text string) bool {
	c := normalizeCode(text)
	if len(c) != codeLen {
		return false
	}
	for _, r := range c {
		if !strings.ContainsRune(codeAlphabet, r) {
			return false
		}
	}
	return true
}

// RedeemResult is the outcome of a pairing attempt.
type RedeemResult int

// Pairing outcomes.
const (
	RedeemOK RedeemResult = iota
	RedeemBad
	RedeemLimited
)

// Redeem checks a code for chat. On success the code is spent and the granted role returned.
func (g *Gate) Redeem(chat Chat, code string) (string, RedeemResult) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.expireLocked()
	recent := g.bad[chat.ID][:0]
	for _, t := range g.bad[chat.ID] {
		if now.Sub(t) < badCodeWindow {
			recent = append(recent, t)
		}
	}
	g.bad[chat.ID] = recent
	if len(recent) >= maxBadCodes {
		return "", RedeemLimited
	}
	code = normalizeCode(code)
	for c, p := range g.codes {
		if len(c) == len(code) && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			delete(g.codes, c)
			delete(g.bad, chat.ID)
			delete(g.strangers, chat.ID)
			role := p.role
			if role == roleOwner && chat.Type != "private" {
				// Everyone in a group could press an owner's buttons.
				role = roleViewer
			}
			if chat.Type == "channel" {
				role = roleAlerts
			}
			return role, RedeemOK
		}
	}
	g.bad[chat.ID] = append(g.bad[chat.ID], now)
	if len(g.bad) > maxBadChats {
		// A flood of wrong codes from ever new chats must not grow memory: the chat whose last
		// wrong code is oldest is forgotten (it is the nearest to its window's end anyway).
		// Never the chat just recorded: with equal timestamps (a coarse router clock during a flood)
		// "oldest" was whichever entry the map yielded first, and evicting the sender reset its own
		// count - wrong codes from one chat plus a flood from fresh ones defeated the limit (QA-057).
		var oldest int64
		var at time.Time
		for id, ts := range g.bad {
			if id == chat.ID {
				continue
			}
			if last := ts[len(ts)-1]; at.IsZero() || last.Before(at) {
				oldest, at = id, last
			}
		}
		delete(g.bad, oldest)
	}
	return "", RedeemBad
}

func (g *Gate) expireLocked() {
	now := g.now()
	for c, p := range g.codes {
		if now.After(p.exp) {
			delete(g.codes, c)
		}
	}
	for id, s := range g.strangers {
		if now.Sub(s.LastSeen) > strangerTTL {
			delete(g.strangers, id)
		}
	}
	// Wrong codes count for badCodeWindow; a chat with none left inside it was kept for good.
	for id, ts := range g.bad {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= badCodeWindow {
			delete(g.bad, id)
		}
	}
	for id := range g.limitTold {
		if _, ok := g.bad[id]; !ok {
			delete(g.limitTold, id)
		}
	}
}

// tellLimited reports whether a chat that Redeem found locked out should be told so now: once per
// refuseEvery, like Seen's refusal, and silence in between. Every message during the lockout was
// answered, and each answer could sit out Telegram's flood control in a handler slot (QA-099).
func (g *Gate) tellLimited(chatID int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if at, ok := g.limitTold[chatID]; ok && now.Sub(at) < refuseEvery {
		return false
	}
	g.limitTold[chatID] = now
	return true
}

// Seen records an unpaired chat and reports whether it should get the refusal text now.
func (g *Gate) Seen(chat Chat, from *User) (refuse bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.expireLocked()
	s := g.strangers[chat.ID]
	if s == nil {
		if len(g.strangers) >= maxStrangers {
			// Keep the newest; a flood of strangers must not grow memory.
			var oldest *Stranger
			for _, x := range g.strangers {
				if oldest == nil || x.LastSeen.Before(oldest.LastSeen) {
					oldest = x
				}
			}
			delete(g.strangers, oldest.ChatID)
		}
		s = &Stranger{ChatID: chat.ID, Type: chat.Type, FirstSeen: now}
		g.strangers[chat.ID] = s
	}
	s.Name, s.Username = chat.DisplayName(), chat.Username
	if from != nil {
		if chat.Type == "private" {
			s.Name, s.Username = from.DisplayName(), from.Username
		}
		s.Lang = from.LanguageCode
	}
	s.LastSeen = now
	s.Attempts++
	if now.Sub(s.refusedAt) < refuseEvery {
		return false
	}
	s.refusedAt = now
	return true
}

// Strangers lists recent unpaired chats, newest first.
func (g *Gate) Strangers() []Stranger {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expireLocked()
	out := make([]Stranger, 0, len(g.strangers))
	for _, s := range g.strangers {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Forget drops a stranger (it was allowed or dismissed in the panel).
func (g *Gate) Forget(chatID int64) (Stranger, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.strangers[chatID]
	if !ok {
		return Stranger{}, false
	}
	delete(g.strangers, chatID)
	return *s, true
}
