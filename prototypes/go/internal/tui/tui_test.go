package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/heimdall-g02/proto-go/internal/profile"
)

func dests(n int) []profile.Destination {
	var ds []profile.Destination
	for i := 0; i < n; i++ {
		ds = append(ds, profile.Destination{Alias: fmt.Sprintf("host-%03d", i), Host: fmt.Sprintf("h%03d.example.internal", i), Account: "aman", Port: 22})
	}
	ds = append(ds, profile.Destination{Alias: "vps-東京", Host: "vps1.example.invalid", Account: "deploy", Port: 2222})
	return ds
}

func press(m *Model, keys ...tea.KeyPressMsg) {
	for _, k := range keys {
		m.Update(k)
	}
}

func txt(s string) tea.KeyPressMsg { return tea.KeyPressMsg{Code: []rune(s)[0], Text: s} }

func TestLayoutWideNarrowTiny(t *testing.T) {
	m := New(dests(3), true)
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	out := m.Render()
	if !strings.Contains(out, "> host-000  aman@h000.example.internal:22") || !strings.Contains(out, "4/4") {
		t.Fatal(out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("SGR with NO_COLOR")
	}
	m.Update(tea.WindowSizeMsg{Width: 49, Height: 10})
	if out = m.Render(); strings.Contains(out, "@") {
		t.Fatal("narrow should be alias only:", out)
	}
	m.Update(tea.WindowSizeMsg{Width: 20, Height: 5})
	out = m.Render()
	lines := strings.Split(out, "\n")
	if len(lines) != 5 {
		t.Fatalf("20x5 lines=%d", len(lines))
	}
	for _, l := range lines {
		if ansi.StringWidth(l) > 20 {
			t.Fatalf("overflow %q", l)
		}
	}
	for _, sz := range [][2]int{{1, 1}, {0, 0}, {3, 2}} {
		m.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		_ = m.Render()
	}
}

func TestColorSelectionNotColorOnly(t *testing.T) {
	m := New(dests(2), false)
	out := m.Render()
	if !strings.Contains(out, "> host-000") || !strings.Contains(out, "\x1b[") {
		t.Fatal(out)
	}
}

func TestKeysFilterSelect(t *testing.T) {
	m := New(dests(100), true)
	press(m, tea.KeyPressMsg{Code: tea.KeyDown}, txt("j"), txt("k"))
	if m.sel != 1 {
		t.Fatal(m.sel)
	}
	press(m, txt("/"), txt("東"), txt("京"))
	if len(m.shown) != 1 || !strings.Contains(m.Render(), "1/101") {
		t.Fatal(m.Render())
	}
	press(m, tea.KeyPressMsg{Code: tea.KeyBackspace})
	if m.filter != "東" {
		t.Fatalf("%q", m.filter)
	}
	press(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.filter != "" || m.filtering || len(m.shown) != 101 {
		t.Fatal("esc")
	}
	press(m, txt("/"), txt("H"), txt("0"), txt("9"), txt("9"), tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.filtering || len(m.shown) != 1 {
		t.Fatal("enter leaves filter")
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.Outcome != Selected || m.Alias != "host-099" || cmd == nil {
		t.Fatal("select")
	}
	// q inside filter mode appends; outside it quits.
	m = New(dests(3), true)
	press(m, txt("/"))
	if _, cmd := m.Update(txt("q")); m.filter != "q" || cmd != nil {
		t.Fatal("q in filter")
	}
	press(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if _, cmd := m.Update(txt("q")); cmd == nil {
		t.Fatal("quit")
	}
	m = New(dests(3), true)
	m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if m.Outcome != Cancelled {
		t.Fatal("ctrl-c")
	}
}

func TestSanitize(t *testing.T) {
	if strings.ContainsRune(Sanitize("a\x1b]0;x\x07"), 0x1b) {
		t.Fatal("escape kept")
	}
}

// K9 (slice-contract §9): each filter change (appended character, Backspace,
// Esc clear) resets the selection to the first shown row; leaving filter mode
// with Enter keeps the selection.
func TestK9SelectionAfterFilterEdit(t *testing.T) {
	m := New(dests(30), true) // aliases host-000..host-029, vps-東京
	down := tea.KeyPressMsg{Code: tea.KeyDown}
	sel := func() string { return m.dests[m.shown[m.sel]].Alias }

	press(m, txt("/"), txt("h"), down, down)
	if sel() != "host-002" {
		t.Fatal(sel())
	}
	press(m, txt("o")) // append
	if m.sel != 0 || sel() != "host-000" {
		t.Fatalf("append: %d %s", m.sel, sel())
	}
	press(m, down, down, tea.KeyPressMsg{Code: tea.KeyBackspace})
	if m.sel != 0 || m.filter != "h" {
		t.Fatalf("backspace: %d %q", m.sel, m.filter)
	}
	press(m, down, down, down, tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.sel != 0 || m.filter != "" || m.filtering {
		t.Fatalf("esc: %d", m.sel)
	}
	press(m, txt("/"), txt("1"), down, down, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.filtering || m.filter != "1" || m.sel != 2 {
		t.Fatalf("enter must keep selection: %d", m.sel)
	}
	keep := sel()
	if _, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter}); cmd == nil || m.Alias != keep {
		t.Fatalf("selected %q want %q", m.Alias, keep)
	}
}
