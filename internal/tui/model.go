package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type Screen string

const (
	ScreenLock    Screen = "lock"
	ScreenHosts   Screen = "hosts"
	ScreenSecrets Screen = "secrets"
	ScreenKeys    Screen = "keys"
)

type Host struct {
	Name    string
	Address string
	User    string
	Port    int
	Tags    []string
}

type Secret struct {
	Name string
}

type Key struct {
	Name   string
	Type   string
	Status string
}

type Client interface {
	Status(ctx context.Context) (locked bool, err error)
	Unlock(ctx context.Context, passphrase string) error
	ListHosts(ctx context.Context) ([]Host, error)
	ListSecrets(ctx context.Context) ([]Secret, error)
	ListKeys(ctx context.Context) ([]Key, error)
	RevealSecret(ctx context.Context, name string) (string, error)
}

type Options struct {
	Client    Client
	RevealTTL time.Duration
	IsTTY     func() bool
}

type Model struct {
	client Client

	screen Screen
	locked bool
	err    string

	lockInput textinput.Model

	hostsList   list.Model
	secretsList list.Model
	keysList    list.Model

	revealTTL time.Duration
}

type unlockMsg struct {
	err error
}

type loadedMsg struct {
	hosts   []Host
	secrets []Secret
	keys    []Key
	err     error
}

type revealedSecretMsg struct {
	name  string
	value string
	err   error
}

type hideSecretMsg struct {
	name string
}

func Run(opts Options) error {
	if opts.IsTTY != nil && !opts.IsTTY() {
		return fmt.Errorf("tui: requires a tty")
	}
	_, err := tea.NewProgram(NewModel(opts)).Run()
	return err
}

func NewModel(opts Options) Model {
	lockInput := textinput.New()
	lockInput.Placeholder = "Enter passphrase"
	lockInput.EchoMode = textinput.EchoPassword
	lockInput.Focus()

	delegate := list.NewDefaultDelegate()

	hostsList := list.New([]list.Item{}, delegate, 0, 0)
	hostsList.Title = "Hosts"
	hostsList.SetShowStatusBar(false)
	hostsList.SetFilteringEnabled(true)
	hostsList.SetShowHelp(false)
	hostsList.SetSize(80, 20)

	secretsList := list.New([]list.Item{}, delegate, 0, 0)
	secretsList.Title = "Secrets"
	secretsList.SetShowStatusBar(false)
	secretsList.SetFilteringEnabled(true)
	secretsList.SetShowHelp(false)
	secretsList.SetSize(80, 20)

	keysList := list.New([]list.Item{}, delegate, 0, 0)
	keysList.Title = "Keys"
	keysList.SetShowStatusBar(false)
	keysList.SetFilteringEnabled(true)
	keysList.SetShowHelp(false)
	keysList.SetSize(80, 20)

	revealTTL := opts.RevealTTL
	if revealTTL <= 0 {
		revealTTL = 10 * time.Second
	}

	return Model{
		client:      opts.Client,
		screen:      ScreenLock,
		locked:      true,
		lockInput:   lockInput,
		hostsList:   hostsList,
		secretsList: secretsList,
		keysList:    keysList,
		revealTTL:   revealTTL,
	}
}

func (m Model) Init() tea.Cmd {
	if m.client == nil {
		return nil
	}
	return func() tea.Msg {
		locked, err := m.client.Status(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		if locked {
			return nil
		}
		hosts, err := m.client.ListHosts(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		secrets, err := m.client.ListSecrets(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		keys, err := m.client.ListKeys(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		return loadedMsg{
			hosts:   hosts,
			secrets: secrets,
			keys:    keys,
		}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.KeyMsg:
		switch typed.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.hostsList.SetSize(typed.Width, typed.Height-4)
		m.secretsList.SetSize(typed.Width, typed.Height-4)
		m.keysList.SetSize(typed.Width, typed.Height-4)
	}

	if m.locked {
		return m.updateLocked(msg)
	}
	return m.updateUnlocked(msg)
}

func (m Model) View() string {
	if m.locked {
		header := "Heimdall\n\nVault is locked.\n"
		if m.err != "" {
			header += "\nError: " + m.err + "\n"
		}
		return header + "\nPassphrase: " + m.lockInput.View()
	}

	tabs := fmt.Sprintf("[h] Hosts  [s] Secrets  [k] Keys  [l] Lock  [q] Quit\n")
	if m.err != "" {
		tabs += "Error: " + m.err + "\n"
	}
	switch m.screen {
	case ScreenSecrets:
		return tabs + "\n" + m.secretsList.View()
	case ScreenKeys:
		return tabs + "\n" + m.keysList.View()
	default:
		return tabs + "\n" + m.hostsList.View()
	}
}

func (m Model) updateLocked(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.KeyMsg:
		if typed.String() == "enter" {
			passphrase := strings.TrimSpace(m.lockInput.Value())
			if passphrase == "" {
				m.err = "passphrase is required"
				return m, nil
			}
			return m, func() tea.Msg {
				err := m.client.Unlock(context.Background(), passphrase)
				return unlockMsg{err: err}
			}
		}
	case unlockMsg:
		if typed.err != nil {
			m.err = typed.err.Error()
			return m, nil
		}
		m.locked = false
		m.screen = ScreenHosts
		m.lockInput.SetValue("")
		m.err = ""
		return m, m.loadDataCmd()
	case loadedMsg:
		if typed.err != nil {
			m.err = typed.err.Error()
			return m, nil
		}
		m.locked = false
		m.screen = ScreenHosts
		m.populateLists(typed.hosts, typed.secrets, typed.keys)
		return m, nil
	}

	var cmd tea.Cmd
	m.lockInput, cmd = m.lockInput.Update(msg)
	return m, cmd
}

func (m Model) updateUnlocked(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.KeyMsg:
		switch typed.String() {
		case "h":
			m.screen = ScreenHosts
			return m, nil
		case "s":
			m.screen = ScreenSecrets
			return m, nil
		case "k":
			m.screen = ScreenKeys
			return m, nil
		case "l":
			m.locked = true
			m.screen = ScreenLock
			m.err = ""
			m.lockInput.Focus()
			return m, nil
		case "enter":
			if m.screen == ScreenSecrets {
				item, ok := m.secretsList.SelectedItem().(secretItem)
				if !ok {
					return m, nil
				}
				return m, m.revealSecretCmd(item.name)
			}
		case "esc":
			m.screen = ScreenHosts
			return m, nil
		}
	case loadedMsg:
		if typed.err != nil {
			m.err = typed.err.Error()
			return m, nil
		}
		m.populateLists(typed.hosts, typed.secrets, typed.keys)
		return m, nil
	case revealedSecretMsg:
		if typed.err != nil {
			m.err = typed.err.Error()
			return m, nil
		}
		m.setSecretDescription(typed.name, typed.value)
		return m, tea.Tick(m.revealTTL, func(time.Time) tea.Msg {
			return hideSecretMsg{name: typed.name}
		})
	case hideSecretMsg:
		m.setSecretDescription(typed.name, "Press Enter to reveal (re-auth required)")
		return m, nil
	}

	switch m.screen {
	case ScreenSecrets:
		var cmd tea.Cmd
		m.secretsList, cmd = m.secretsList.Update(msg)
		return m, cmd
	case ScreenKeys:
		var cmd tea.Cmd
		m.keysList, cmd = m.keysList.Update(msg)
		return m, cmd
	default:
		var cmd tea.Cmd
		m.hostsList, cmd = m.hostsList.Update(msg)
		return m, cmd
	}
}

func (m Model) loadDataCmd() tea.Cmd {
	return func() tea.Msg {
		hosts, err := m.client.ListHosts(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		secrets, err := m.client.ListSecrets(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		keys, err := m.client.ListKeys(context.Background())
		if err != nil {
			return loadedMsg{err: err}
		}
		return loadedMsg{
			hosts:   hosts,
			secrets: secrets,
			keys:    keys,
		}
	}
}

func (m Model) revealSecretCmd(name string) tea.Cmd {
	return func() tea.Msg {
		value, err := m.client.RevealSecret(context.Background(), name)
		return revealedSecretMsg{name: name, value: value, err: err}
	}
}

func (m *Model) populateLists(hosts []Host, secrets []Secret, keys []Key) {
	hostItems := make([]list.Item, 0, len(hosts))
	for _, host := range hosts {
		description := fmt.Sprintf("%s:%d user=%s", host.Address, host.Port, host.User)
		hostItems = append(hostItems, hostItem{
			name:        host.Name,
			description: description,
		})
	}
	m.hostsList.SetItems(hostItems)
	m.hostsList.NewStatusMessage("Hosts loaded")

	secretItems := make([]list.Item, 0, len(secrets))
	for _, secret := range secrets {
		secretItems = append(secretItems, secretItem{
			name:        secret.Name,
			description: "Press Enter to reveal (re-auth required)",
		})
	}
	m.secretsList.SetItems(secretItems)
	m.secretsList.NewStatusMessage("Secrets loaded")

	keyItems := make([]list.Item, 0, len(keys))
	for _, key := range keys {
		keyItems = append(keyItems, keyItem{
			name:        key.Name,
			description: fmt.Sprintf("type=%s status=%s", key.Type, key.Status),
		})
	}
	m.keysList.SetItems(keyItems)
	m.keysList.NewStatusMessage("Keys loaded")
}

func (m *Model) setSecretDescription(name, description string) {
	items := m.secretsList.Items()
	updated := make([]list.Item, 0, len(items))
	for _, item := range items {
		secret, ok := item.(secretItem)
		if !ok {
			updated = append(updated, item)
			continue
		}
		if secret.name == name {
			secret.description = description
		}
		updated = append(updated, secret)
	}
	m.secretsList.SetItems(updated)
}

type hostItem struct {
	name        string
	description string
}

func (i hostItem) Title() string       { return i.name }
func (i hostItem) Description() string { return i.description }
func (i hostItem) FilterValue() string { return i.name + " " + i.description }

type secretItem struct {
	name        string
	description string
}

func (i secretItem) Title() string       { return i.name }
func (i secretItem) Description() string { return i.description }
func (i secretItem) FilterValue() string { return i.name }

type keyItem struct {
	name        string
	description string
}

func (i keyItem) Title() string       { return i.name }
func (i keyItem) Description() string { return i.description }
func (i keyItem) FilterValue() string { return i.name + " " + i.description }
