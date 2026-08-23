package main

import (
	"encoding/json"
	"fmt"
	"os"

	"wayhop/internal/generator"
	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// runTool handles non-daemon CLI subcommands used for quick testing:
//
//	wayhop import <share-link-or-conf>   # parse a link into the wayhop model (JSON)
//	wayhop gen    <share-link-or-conf>   # parse + wrap in a profile + emit sing-box config
func runTool(args []string) error {
	switch args[0] {
	case "import":
		if len(args) < 2 {
			return fmt.Errorf("usage: wayhop import <share-link-or-conf>")
		}
		e, err := importer.Parse(args[1])
		if err != nil {
			return err
		}
		return printJSON(e)

	case "gen":
		if len(args) < 2 {
			return fmt.Errorf("usage: wayhop gen <share-link-or-conf>")
		}
		e, err := importer.Parse(args[1])
		if err != nil {
			return err
		}
		p := &model.Profile{
			Endpoints: []model.Endpoint{*e},
			Groups:    []model.Group{{ID: "main", Name: "Main", Type: model.GroupURLTest, Members: []string{e.ID}}},
			Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "main"}},
		}
		res, err := generator.Generate(p, generator.Options{MixedPort: 7890, ClashAddr: "127.0.0.1:9090"})
		if err != nil {
			return err
		}
		if len(res.Plugins) > 0 {
			fmt.Fprintf(os.Stderr, "note: %d endpoint(s) need an external engine plugin (e.g. AmneziaWG)\n", len(res.Plugins))
		}
		return printJSON(res.Config)

	case "gen-profile":
		// wayhop gen-profile <profile.json> [tun]
		// Generate the sing-box config from a FULL profile file (e.g. fetched from
		// GET /api/profile), optionally in TUN gateway mode — for offline validation
		// (pipe into `sing-box check`) without touching a running daemon.
		if len(args) < 2 {
			return fmt.Errorf("usage: wayhop gen-profile <profile.json> [tun]")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var p model.Profile
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("parse profile %q: %w", args[1], err)
		}
		opts := generator.Options{MixedPort: 7890, ClashAddr: "127.0.0.1:9090", CacheFile: "cache.db"}
		if len(args) > 2 && args[2] == "tun" {
			opts.TunEnabled = true
		}
		res, err := generator.Generate(&p, opts)
		if err != nil {
			return err
		}
		return printJSON(res.Config)

	default:
		return fmt.Errorf("unknown subcommand %q (try: import, gen, gen-profile)", args[0])
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
