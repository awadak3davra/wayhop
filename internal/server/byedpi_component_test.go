package server

import (
	"reflect"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/updater"
)

// The ciadpi component is needed by the enabled ByeDPI connections, and only by them.
func TestByeDPIComponentUsers(t *testing.T) {
	prof := model.Profile{Endpoints: []model.Endpoint{
		{ID: "bye", Name: "ByeDPI home", Engine: model.EngineByeDPI, Enabled: true},
		{ID: "bye2", Engine: model.EngineByeDPI, Enabled: false},
		{ID: "nl", Name: "NL", Engine: model.EngineSingBox, Enabled: true},
	}}
	e := updater.EngineByID("byedpi")
	if e == nil || e.Role != "socks-plugin" {
		t.Fatalf("catalog entry = %+v", e)
	}
	if got := engineUsers(prof, model.Engine(e.ID)); !reflect.DeepEqual(got, []string{"ByeDPI home"}) {
		t.Errorf("users = %v", got)
	}
}
