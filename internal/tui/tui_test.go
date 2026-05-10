package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/athanvi/heimdall/internal/doctor"
	"github.com/athanvi/heimdall/internal/model"
)

func TestViewShowsCorePanelsAndFindings(t *testing.T) {
	m := modelState{
		cfg: model.Config{
			Contexts:   map[string]model.Context{"ctx": {}},
			HostRoutes: map[string]model.HostRoute{"host": {}},
		},
		report: doctor.Report{Findings: []model.DiagnosticFinding{{
			ID: "HD-TEST", Severity: "warning", Title: "fixture finding",
		}}},
	}
	view := m.View()
	for _, want := range []string{"Heimdall", "dashboard", "diagnostics", "HD-TEST", "fixture finding"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}
}

func TestUpdateSelectionAndQuit(t *testing.T) {
	m := modelState{report: doctor.Report{Findings: []model.DiagnosticFinding{{ID: "A"}, {ID: "B"}}}}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	updated := next.(modelState)
	if updated.selected != 1 {
		t.Fatalf("selection did not move down: %#v", updated)
	}
	next, cmd := updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatalf("quit did not return command, next=%#v", next)
	}
}
