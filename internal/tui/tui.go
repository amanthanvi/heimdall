package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/athanvi/heimdall/internal/doctor"
	"github.com/athanvi/heimdall/internal/model"
)

type modelState struct {
	cfg      model.Config
	report   doctor.Report
	err      error
	selected int
}

func Run(ctx context.Context, cfg model.Config) error {
	report, err := doctor.Engine{}.Run(ctx, cfg, doctor.Options{})
	m := modelState{cfg: cfg, report: report, err: err}
	_, runErr := tea.NewProgram(m).Run()
	if runErr != nil {
		return runErr
	}
	return err
}

func (m modelState) Init() tea.Cmd { return nil }

func (m modelState) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "down", "j":
			if m.selected < len(m.report.Findings)-1 {
				m.selected++
			}
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "r", "d":
			report, err := doctor.Engine{}.Run(context.Background(), m.cfg, doctor.Options{})
			m.report = report
			m.err = err
		}
	}
	return m, nil
}

func (m modelState) View() string {
	var b strings.Builder
	b.WriteString("Heimdall\n")
	b.WriteString("tab panels: dashboard diagnostics identities agents contexts routes sessions certs wsl containers transports settings\n")
	if m.err != nil {
		b.WriteString("error: " + m.err.Error() + "\n")
	}
	b.WriteString(fmt.Sprintf("routes: %d  contexts: %d  findings: %d\n\n", len(m.cfg.HostRoutes), len(m.cfg.Contexts), len(m.report.Findings)))
	if len(m.report.Findings) == 0 {
		b.WriteString("No findings. Press r to refresh, q to quit.\n")
		return b.String()
	}
	for i, finding := range m.report.Findings {
		prefix := "  "
		if i == m.selected {
			prefix = "> "
		}
		b.WriteString(fmt.Sprintf("%s[%s] %s %s\n", prefix, finding.Severity, finding.ID, finding.Title))
	}
	b.WriteString("\nPress r/d to refresh doctor, arrows to select, q to quit.\n")
	return b.String()
}
