package tui

import (
	"context"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestModelStartsLockedAndTransitionsAfterUnlock(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		locked: true,
		hosts: []Host{
			{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"},
		},
		secrets: []Secret{{Name: "api-token"}},
		keys:    []Key{{Name: "deploy", Type: "ed25519", Status: "active"}},
	}

	model := NewModel(Options{Client: client, RevealTTL: time.Second})
	require.True(t, model.locked)
	require.Equal(t, ScreenLock, model.screen)

	model.lockInput.SetValue("correct-pass")
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)
	msg := cmd()
	require.IsType(t, unlockMsg{}, msg)

	nextModel, loadCmd := updated.(Model).Update(msg)
	require.NotNil(t, loadCmd)
	loadMsg := loadCmd()
	require.IsType(t, loadedMsg{}, loadMsg)

	finalModel, _ := nextModel.(Model).Update(loadMsg)
	state := finalModel.(Model)
	require.False(t, state.locked)
	require.Equal(t, ScreenHosts, state.screen)
	require.NotEmpty(t, state.hostsList.Items())
}

func TestModelInitStartsOnHostListWhenAlreadyUnlocked(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		locked:  false,
		hosts:   []Host{{Name: "web", Address: "10.0.0.2", Port: 22, User: "deploy"}},
		secrets: []Secret{{Name: "db-pass"}},
		keys:    []Key{{Name: "infra", Type: "rsa", Status: "active"}},
	}
	model := NewModel(Options{Client: client})

	cmd := model.Init()
	require.NotNil(t, cmd)
	msg := cmd()
	require.IsType(t, loadedMsg{}, msg)

	next, _ := model.Update(msg)
	state := next.(Model)
	require.False(t, state.locked)
	require.Equal(t, ScreenHosts, state.screen)
	require.Contains(t, state.View(), "Hosts")
}

func TestSecretViewRedactsByDefaultAndAutoHidesAfterReveal(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		locked:  false,
		hosts:   []Host{{Name: "db", Address: "10.0.0.3", Port: 22, User: "ops"}},
		secrets: []Secret{{Name: "token"}},
		keys:    []Key{{Name: "ops", Type: "ed25519", Status: "active"}},
		values:  map[string]string{"token": "very-secret-value"},
	}
	model := NewModel(Options{Client: client, RevealTTL: 10 * time.Millisecond})

	msg := model.Init()()
	updated, _ := model.Update(msg)
	state := updated.(Model)
	state.screen = ScreenSecrets

	view := state.View()
	require.Contains(t, view, "Press Enter to reveal")
	require.NotContains(t, view, "very-secret-value")

	next, revealCmd := state.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, revealCmd)
	revealMsg := revealCmd()
	require.IsType(t, revealedSecretMsg{}, revealMsg)

	revealedModel, hideCmd := next.(Model).Update(revealMsg)
	require.NotNil(t, hideCmd)
	view = revealedModel.(Model).View()
	require.Contains(t, view, "very-secret-value")

	hiddenModel, _ := revealedModel.(Model).Update(hideSecretMsg{name: "token"})
	view = hiddenModel.(Model).View()
	require.Contains(t, view, "Press Enter to reveal")
	require.NotContains(t, view, "very-secret-value")
}

type fakeClient struct {
	locked  bool
	hosts   []Host
	secrets []Secret
	keys    []Key
	values  map[string]string
}

func (f *fakeClient) Status(context.Context) (bool, error) {
	return f.locked, nil
}

func (f *fakeClient) Unlock(context.Context, string) error {
	f.locked = false
	return nil
}

func (f *fakeClient) ListHosts(context.Context) ([]Host, error) {
	return append([]Host(nil), f.hosts...), nil
}

func (f *fakeClient) ListSecrets(context.Context) ([]Secret, error) {
	return append([]Secret(nil), f.secrets...), nil
}

func (f *fakeClient) ListKeys(context.Context) ([]Key, error) {
	return append([]Key(nil), f.keys...), nil
}

func (f *fakeClient) RevealSecret(_ context.Context, name string) (string, error) {
	return f.values[name], nil
}
