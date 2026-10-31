package importer

import (
	"errors"
	"net/url"
	"strings"
	"unicode"

	"wayhop/internal/model"
)

// An SSH exit has no share-link standard; two sources carry one.
//
//   - ssh://user[:password]@host[:port][#name], the URI form ssh(1) also takes as a destination. It holds no
//     private key or host key, so a key login and the pin are added in the confirmation form, and
//     the review says while no host key is pinned. A ";fingerprint=" parameter on the user (the
//     IETF draft URI form) is an MD5 or SHA-256 fingerprint, which sing-box cannot pin, so it is
//     dropped rather than read as part of the user name. The query is ignored.
//   - a sing-box config's ssh outbound, which is what WayHop itself writes (Generate -> ParseSingbox).
//
// A Clash / mihomo `type: ssh` proxy is not read: its private-key is a file path or a YAML block
// scalar, neither of which the Clash reader here can carry, and a half-read key is worse than the
// reader's "unsupported clash proxy type" answer.
//
// None of the errors quote a password or a key.

// What an ssh:// link can express (sourceFields): the user and a password. A private key, its
// passphrase and the server's host keys are never in one; they are typed in the form, and a
// re-import keeps them.
var sshLinkFields = sourceFields{params: []string{"user", "password"}}

func parseSSHURL(u *url.URL) (*model.Endpoint, error) {
	user := u.User.Username()
	if i := strings.IndexByte(user, ';'); i >= 0 {
		user = user[:i]
	}
	// url.Parse decodes %0A and the like into the user name. No server has such a login, and
	// model.Validate refuses it too; saying so here names the link rather than a stored draft.
	if strings.IndexFunc(user, unicode.IsControl) >= 0 {
		return nil, errors.New("the user name in the ssh:// link holds a line break or other control character")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoSSH,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 22),
		Name:     fragmentName(u),
		Params:   map[string]any{},
	}
	if user != "" {
		e.Params["user"] = user
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		e.Params["password"] = pw
	}
	return e, nil
}

// fillSSHFromSingbox reads a sing-box ssh outbound into the params generator/ssh.go renders. A key
// named by path is refused: the router cannot read a file on the machine the config came from.
// host_key_algorithms is not kept; the generator offers exactly the pinned key types.
func fillSSHFromSingbox(e *model.Endpoint, ob map[string]any) error {
	e.Protocol = model.ProtoSSH
	if err := sbRefuseFiles(ob, "private_key_path"); err != nil {
		return err
	}
	if e.Port == 0 {
		e.Port = 22 // sing-box's own default for server_port
	}
	for _, k := range []string{"user", "password", "private_key_passphrase", "client_version"} {
		if s := sbStr(ob, k); s != "" {
			e.Params[k] = s
		}
	}
	if k := strings.TrimSpace(sbText(ob, "private_key")); k != "" {
		e.Params["private_key"] = k
	}
	for _, k := range []string{"host_key", "cipher", "mac", "kex_algorithm"} {
		if l := sbLines(ob, k); len(l) > 0 {
			e.Params[k] = l
		}
	}
	return nil
}

// sbLines reads a sing-box listable string field as a list.
func sbLines(m map[string]any, k string) []string {
	var out []string
	switch v := m[k].(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}
