package tui

import (
	"context"
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestModelInitStartsOnLockScreenWhenVaultLocked(t *testing.T) {
	t.Parallel()

	client := &fakeClient{locked: true}
	model := NewModel(Options{Client: client})
	state := model

	require.True(t, state.locked)
	require.Equal(t, ScreenLock, state.screen)
	require.Contains(t, state.View(), "Vault is locked")
}

func TestModelInitStartsOnHostListWhenVaultUnlocked(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked: false,
		hosts:  []Host{{Name: "web", Address: "10.0.0.2", Port: 22, User: "deploy"}},
	})

	require.False(t, state.locked)
	require.Equal(t, ScreenHosts, state.screen)
	require.Contains(t, state.View(), "Hosts")
}

func TestLockScreenPassphraseInputSubmitsUnlockRequest(t *testing.T) {
	t.Parallel()

	client := &fakeClient{locked: true}
	model := NewModel(Options{Client: client})
	model.lockInput.SetValue("correct-passphrase")

	next, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)

	msg := cmd()
	require.IsType(t, unlockMsg{}, msg)
	_, _ = next.(Model).Update(msg)
	require.Equal(t, "correct-passphrase", client.lastUnlockPassphrase)
}

func TestHostListDisplaysHostNamesAndTags(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked: false,
		hosts:  []Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu", Tags: []string{"critical", "group:infra"}}},
	})

	view := state.View()
	require.Contains(t, view, "prod")
	require.Contains(t, view, "critical")
}

func TestHostListSearchFiltersResults(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked: false,
		hosts: []Host{
			{Name: "prod-web", Address: "10.0.0.1", Port: 22, User: "ubuntu"},
			{Name: "dev-api", Address: "10.0.0.2", Port: 22, User: "deploy"},
		},
	})

	state.hostsList.SetFilterText("prod")
	visible := state.hostsList.VisibleItems()
	require.Len(t, visible, 1)
	require.Contains(t, visible[0].FilterValue(), "prod-web")
}

func TestHostListEmptyStateShowsOnboardingMessage(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{locked: false})
	require.Contains(t, state.View(), "No hosts yet")
	require.Contains(t, state.View(), "Press 'a' to add")
}

func TestHostDetailShowsHostConfigFields(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked: false,
		hosts:  []Host{{Name: "db", Address: "10.0.0.9", Port: 2222, User: "ops", Tags: []string{"prod"}}},
	})

	next, _ := state.Update(tea.KeyMsg{Type: tea.KeyEnter})
	detail := next.(Model)

	require.Equal(t, ScreenHostDetail, detail.screen)
	view := detail.View()
	require.Contains(t, view, "Name: db")
	require.Contains(t, view, "Address: 10.0.0.9")
	require.Contains(t, view, "User: ops")
	require.Contains(t, view, "Port: 2222")
}

func TestSecretListShowsNamesOnlyValuesHidden(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked:  false,
		secrets: []Secret{{Name: "token"}},
		values:  map[string]string{"token": "very-secret-value"},
	})
	state.screen = ScreenSecrets

	view := state.View()
	require.Contains(t, view, "token")
	require.Contains(t, view, "Press Enter to reveal")
	require.NotContains(t, view, "very-secret-value")
}

func TestSecretRevealTriggersReauthFlowBeforeDisplay(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		locked:  false,
		secrets: []Secret{{Name: "token"}},
		values:  map[string]string{"token": "very-secret-value"},
	}
	state := buildUnlockedModel(t, client)
	state.screen = ScreenSecrets

	next, cmd := state.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.Nil(t, cmd)
	withReauth := next.(Model)
	require.Equal(t, ScreenReauth, withReauth.screen)
	require.Empty(t, client.revealedNames)

	withReauth.reauthInput.SetValue("reauth-pass")
	next, cmd = withReauth.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)
	reauthResult := cmd()
	require.IsType(t, reauthMsg{}, reauthResult)

	next, revealCmd := next.(Model).Update(reauthResult)
	require.NotNil(t, revealCmd)
	revealMsg := revealCmd()
	final, _ := next.(Model).Update(revealMsg)

	require.Equal(t, "reauth-pass", client.lastReauthPassphrase)
	require.Contains(t, client.revealedNames, "token")
	require.Contains(t, final.(Model).View(), "very-secret-value")
}

func TestSecretRevealAutoHidesAfterTimeout(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		locked:  false,
		secrets: []Secret{{Name: "token"}},
		values:  map[string]string{"token": "very-secret-value"},
	}
	state := buildUnlockedModel(t, client)
	state.screen = ScreenSecrets

	next, _ := state.Update(tea.KeyMsg{Type: tea.KeyEnter})
	withReauth := next.(Model)
	withReauth.reauthInput.SetValue("reauth-pass")
	next, reauthCmd := withReauth.Update(tea.KeyMsg{Type: tea.KeyEnter})
	reauthMsg := reauthCmd()
	next, revealCmd := next.(Model).Update(reauthMsg)
	revealMsg := revealCmd()
	revealed, hideCmd := next.(Model).Update(revealMsg)

	hideMsg := hideCmd()
	hidden, _ := revealed.(Model).Update(hideMsg)
	view := hidden.(Model).View()
	require.Contains(t, view, "Press Enter to reveal")
	require.NotContains(t, view, "very-secret-value")
}

func TestAddEditFormRendersExpectedFields(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{locked: false})
	next, _ := state.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})

	form := next.(Model)
	require.Equal(t, ScreenForm, form.screen)
	view := form.View()
	require.Contains(t, view, "Add/Edit Form")
	require.Contains(t, view, "name")
	require.Contains(t, view, "address")
	require.Contains(t, view, "user")
	require.Contains(t, view, "port")
}

func TestDestructiveActionShowsConfirmDialogBeforeDelete(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked: false,
		hosts:  []Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
	})
	next, _ := state.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})

	confirm := next.(Model)
	require.Equal(t, ScreenConfirm, confirm.screen)
	require.Contains(t, confirm.View(), "Delete selected host")
}

func TestESCCancelsCurrentActionAndReturnsToPreviousScreen(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{locked: false})
	next, _ := state.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	form := next.(Model)
	require.Equal(t, ScreenForm, form.screen)

	next, _ = form.Update(tea.KeyMsg{Type: tea.KeyEsc})
	cancelled := next.(Model)
	require.Equal(t, ScreenHosts, cancelled.screen)
}

func TestRedactionViewNeverContainsSecretValuesWithoutExplicitReveal(t *testing.T) {
	t.Parallel()

	state := buildUnlockedModel(t, &fakeClient{
		locked:  false,
		secrets: []Secret{{Name: "token"}},
		values:  map[string]string{"token": "very-secret-value"},
	})
	state.screen = ScreenSecrets

	view := state.View()
	require.NotContains(t, view, "very-secret-value")
}

func TestRunRefusesStartOnNonTTY(t *testing.T) {
	t.Parallel()

	err := Run(Options{
		Client: &fakeClient{locked: true},
		IsTTY:  func() bool { return false },
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires a tty")
}

func buildUnlockedModel(t *testing.T, client *fakeClient) Model {
	t.Helper()

	model := NewModel(Options{Client: client, RevealTTL: time.Millisecond})
	msg := model.Init()
	if msg == nil {
		return model
	}
	loaded := msg()
	next, _ := model.Update(loaded)
	return next.(Model)
}

type fakeClient struct {
	locked               bool
	hosts                []Host
	secrets              []Secret
	keys                 []Key
	passkeys             []Passkey
	values               map[string]string
	reauthErr            error
	lastUnlockPassphrase string
	lastReauthPassphrase string
	revealedNames        []string
}

func (f *fakeClient) Status(context.Context) (bool, error) {
	return f.locked, nil
}

func (f *fakeClient) Unlock(_ context.Context, passphrase string) error {
	f.lastUnlockPassphrase = passphrase
	f.locked = false
	return nil
}

func (f *fakeClient) Reauth(_ context.Context, passphrase string) error {
	f.lastReauthPassphrase = passphrase
	if f.reauthErr != nil {
		return f.reauthErr
	}
	if passphrase == "" {
		return errors.New("missing passphrase")
	}
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

func (f *fakeClient) ListPasskeys(context.Context) ([]Passkey, error) {
	return append([]Passkey(nil), f.passkeys...), nil
}

func (f *fakeClient) RevealSecret(_ context.Context, name string) (string, error) {
	f.revealedNames = append(f.revealedNames, name)
	return f.values[name], nil
}
