// Package tui is the Bubble Tea destination picker (docs/g02/slice-contract.md
// §5). It consumes the shared profile package (validation and Filter) and
// performs no I/O of its own.
package tui

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/heimdall-g02/proto-go/internal/profile"
)

// Outcome of an interactive session.
type Outcome int

const (
	Quit Outcome = iota
	Selected
	Cancelled  // Ctrl-C / SIGINT
	Terminated // SIGTERM
	HungUp     // SIGHUP / terminal hangup (K10)
)

// TermMsg is sent by the caller's SIGTERM handler.
type TermMsg struct{}

// HangupMsg is sent by the caller's SIGHUP handler.
type HangupMsg struct{}

// Model is the picker state.
type Model struct {
	dests     []profile.Destination
	shown     []int
	sel       int
	filter    string
	filtering bool
	width     int
	height    int
	noColor   bool

	Outcome Outcome
	Alias   string
}

// New builds a model. noColor disables every color SGR sequence.
func New(dests []profile.Destination, noColor bool) *Model {
	m := &Model{dests: dests, noColor: noColor, width: 80, height: 24}
	m.shown = profile.Filter(dests, "")
	return m
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) refilter() {
	m.shown = profile.Filter(m.dests, m.filter)
	m.sel = 0
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.InterruptMsg:
		m.Outcome = Cancelled
		return m, tea.Quit
	case TermMsg:
		m.Outcome = Terminated
		return m, tea.Quit
	case HangupMsg:
		m.Outcome = HungUp
		return m, tea.Quit
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *Model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if k.Keystroke() == "ctrl+c" {
		m.Outcome = Cancelled
		return m, tea.Quit
	}
	switch k.Code {
	case tea.KeyUp:
		m.move(-1)
		return m, nil
	case tea.KeyDown:
		m.move(1)
		return m, nil
	}
	if m.filtering {
		switch k.Code {
		case tea.KeyEnter:
			m.filtering = false
		case tea.KeyEscape:
			m.filtering = false
			m.filter = ""
			m.refilter()
		case tea.KeyBackspace:
			if m.filter != "" {
				_, size := utf8.DecodeLastRuneInString(m.filter)
				m.filter = m.filter[:len(m.filter)-size]
				m.refilter()
			}
		default:
			if k.Text != "" && k.Mod&^tea.ModShift == 0 && printable(k.Text) {
				m.filter += k.Text
				m.refilter()
			}
		}
		return m, nil
	}
	switch {
	case k.Code == tea.KeyEnter:
		if len(m.shown) > 0 {
			m.Outcome = Selected
			m.Alias = m.dests[m.shown[m.sel]].Alias
			return m, tea.Quit
		}
	case k.Text == "k":
		m.move(-1)
	case k.Text == "j":
		m.move(1)
	case k.Text == "/":
		m.filtering = true
	case k.Text == "q":
		m.Outcome = Quit
		return m, tea.Quit
	}
	return m, nil
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func (m *Model) move(d int) {
	if len(m.shown) == 0 {
		return
	}
	m.sel = max(0, min(len(m.shown)-1, m.sel+d))
}

// Sanitize replaces control characters so profile strings cannot emit
// terminal escapes on screen or in the SELECTED line.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return utf8.RuneError
		}
		return r
	}, s)
}

const (
	sgrSelected = "\x1b[1;36m" // bold cyan; never the only selection cue
	sgrReset    = "\x1b[0m"
)

// Render is the pure layout function (exported for tests).
func (m *Model) Render() string {
	w, h := max(m.width, 1), max(m.height, 1)
	rows := h - 1 // last line is the status line
	var b strings.Builder
	start := 0
	if rows > 0 && m.sel >= rows {
		start = m.sel - rows + 1
	}
	for i := 0; i < rows; i++ {
		idx := start + i
		if idx < len(m.shown) {
			d := m.dests[m.shown[idx]]
			text := Sanitize(d.Alias)
			if w >= 50 {
				text = fmt.Sprintf("%s  %s@%s:%d", Sanitize(d.Alias), Sanitize(d.Account), Sanitize(d.Host), d.Port)
			}
			prefix := "  "
			if idx == m.sel {
				prefix = "> "
			}
			line := ansi.Truncate(prefix+text, w, "")
			if idx == m.sel && !m.noColor {
				line = sgrSelected + line + sgrReset
			}
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	status := fmt.Sprintf("%d/%d", len(m.shown), len(m.dests))
	if m.filtering {
		status += " /" + Sanitize(m.filter)
	} else if m.filter != "" {
		status += " filter:" + Sanitize(m.filter)
	}
	b.WriteString(ansi.Truncate(status, w, ""))
	return b.String()
}

func (m *Model) View() tea.View {
	v := tea.NewView(m.Render())
	v.AltScreen = true
	// Cursor nil => hidden while active.
	return v
}
