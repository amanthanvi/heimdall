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
	ScreenLock       Screen = "lock"
	ScreenHosts      Screen = "hosts"
	ScreenHostDetail Screen = "host_detail"
	ScreenSecrets    Screen = "secrets"
	ScreenKeys       Screen = "keys"
	ScreenPasskeys   Screen = "passkeys"
	ScreenForm       Screen = "form"
	ScreenConfirm    Screen = "confirm"
	ScreenReauth     Screen = "reauth"
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

type Passkey struct {
	Label              string
	SupportsHMACSecret bool
}

type Client interface {
	Status(ctx context.Context) (locked bool, err error)
	Unlock(ctx context.Context, passphrase string) error
	Reauth(ctx context.Context, passphrase string) error
	ListHosts(ctx context.Context) ([]Host, error)
	ListSecrets(ctx context.Context) ([]Secret, error)
	ListKeys(ctx context.Context) ([]Key, error)
	ListPasskeys(ctx context.Context) ([]Passkey, error)
	RevealSecret(ctx context.Context, name string) (string, error)
}

type Options struct {
	Client    Client
	RevealTTL time.Duration
	IsTTY     func() bool
}

type Model struct {
	client Client

	screen   Screen
	previous Screen
	locked   bool
	err      string

	lockInput   textinput.Model
	reauthInput textinput.Model

	hostsList    list.Model
	secretsList  list.Model
	keysList     list.Model
	passkeysList list.Model

	revealTTL         time.Duration
	hostsByName       map[string]Host
	selectedHostName  string
	pendingSecretName string
	confirmPrompt     string
}

type unlockMsg struct {
	err error
}

type loadedMsg struct {
	hosts    []Host
	secrets  []Secret
	keys     []Key
	passkeys []Passkey
	err      error
}

type reauthMsg struct {
	err error
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

	reauthInput := textinput.New()
	reauthInput.Placeholder = "Re-authenticate to reveal"
	reauthInput.EchoMode = textinput.EchoPassword

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

	passkeysList := list.New([]list.Item{}, delegate, 0, 0)
	passkeysList.Title = "Passkeys"
	passkeysList.SetShowStatusBar(false)
	passkeysList.SetFilteringEnabled(true)
	passkeysList.SetShowHelp(false)
	passkeysList.SetSize(80, 20)

	revealTTL := opts.RevealTTL
	if revealTTL <= 0 {
		revealTTL = 10 * time.Second
	}

	return Model{
		client:        opts.Client,
		screen:        ScreenLock,
		locked:        true,
		lockInput:     lockInput,
		reauthInput:   reauthInput,
		hostsList:     hostsList,
		secretsList:   secretsList,
		keysList:      keysList,
		passkeysList:  passkeysList,
		revealTTL:     revealTTL,
		hostsByName:   map[string]Host{},
		confirmPrompt: "",
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
		return loadData(m.client)
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
		height := typed.Height - 4
		if height < 1 {
			height = 1
		}
		m.hostsList.SetSize(typed.Width, height)
		m.secretsList.SetSize(typed.Width, height)
		m.keysList.SetSize(typed.Width, height)
		m.passkeysList.SetSize(typed.Width, height)
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

	tabs := "[h] Hosts  [s] Secrets  [k] Keys  [p] Passkeys  [a] Add  [d] Delete  [l] Lock  [q] Quit\n"
	if m.err != "" {
		tabs += "Error: " + m.err + "\n"
	}

	switch m.screen {
	case ScreenHostDetail:
		return tabs + "\n" + m.renderHostDetailView()
	case ScreenSecrets:
		if len(m.secretsList.Items()) == 0 {
			return tabs + "\n" + renderEmptyState("No secrets yet.", "Add one with `heimdall secret add ...`")
		}
		return tabs + "\n" + m.secretsList.View()
	case ScreenKeys:
		if len(m.keysList.Items()) == 0 {
			return tabs + "\n" + renderEmptyState("No keys yet.", "Add one with `heimdall key gen --name ...`")
		}
		return tabs + "\n" + m.keysList.View()
	case ScreenPasskeys:
		if len(m.passkeysList.Items()) == 0 {
			return tabs + "\n" + renderEmptyState("No passkeys yet.", "Enroll one with `heimdall passkey enroll --label ...`")
		}
		return tabs + "\n" + m.passkeysList.View()
	case ScreenForm:
		return tabs + "\n" + "Add/Edit Form\n\nFields: name, address, user, port, tags\n\nPress ESC to cancel."
	case ScreenConfirm:
		prompt := m.confirmPrompt
		if prompt == "" {
			prompt = "Confirm action?"
		}
		return tabs + "\n" + prompt + "\n\n[y] Confirm  [n]/[esc] Cancel"
	case ScreenReauth:
		return tabs + "\nRe-authentication required\n\nPassphrase: " + m.reauthInput.View()
	default:
		if len(m.hostsList.Items()) == 0 {
			return tabs + "\n" + renderEmptyState("No hosts yet.", "Press 'a' to add your first host.")
		}
		return tabs + "\n" + m.hostsList.View()
	}
}

func renderEmptyState(title, guidance string) string {
	return title + "\n" + guidance
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
		m.populateLists(typed.hosts, typed.secrets, typed.keys, typed.passkeys)
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
		case "p":
			m.screen = ScreenPasskeys
			return m, nil
		case "l":
			m.locked = true
			m.screen = ScreenLock
			m.err = ""
			m.pendingSecretName = ""
			m.clearRevealedSecrets()
			m.lockInput.Focus()
			return m, nil
		case "a":
			m.previous = m.screen
			m.screen = ScreenForm
			return m, nil
		case "d":
			m.previous = m.screen
			m.screen = ScreenConfirm
			if m.previous == ScreenSecrets {
				m.confirmPrompt = "Delete selected secret?"
			} else {
				m.confirmPrompt = "Delete selected host?"
			}
			return m, nil
		case "y":
			if m.screen == ScreenConfirm {
				m.screen = m.previous
				return m, nil
			}
		case "n":
			if m.screen == ScreenConfirm {
				m.screen = m.previous
				return m, nil
			}
		case "enter":
			switch m.screen {
			case ScreenHosts:
				item, ok := m.hostsList.SelectedItem().(hostItem)
				if !ok {
					return m, nil
				}
				m.selectedHostName = item.name
				m.previous = ScreenHosts
				m.screen = ScreenHostDetail
				return m, nil
			case ScreenSecrets:
				item, ok := m.secretsList.SelectedItem().(secretItem)
				if !ok {
					return m, nil
				}
				m.pendingSecretName = item.name
				m.previous = ScreenSecrets
				m.screen = ScreenReauth
				m.reauthInput.SetValue("")
				m.reauthInput.Focus()
				return m, nil
			case ScreenReauth:
				passphrase := strings.TrimSpace(m.reauthInput.Value())
				if passphrase == "" {
					m.err = "passphrase is required"
					return m, nil
				}
				return m, m.reauthCmd(passphrase)
			case ScreenConfirm:
				m.screen = m.previous
				return m, nil
			}
		case "esc":
			switch m.screen {
			case ScreenHostDetail, ScreenForm, ScreenConfirm, ScreenReauth:
				if m.previous == "" {
					m.screen = ScreenHosts
				} else {
					m.screen = m.previous
				}
				m.confirmPrompt = ""
				m.pendingSecretName = ""
				return m, nil
			default:
				m.screen = ScreenHosts
				return m, nil
			}
		}
	case loadedMsg:
		if typed.err != nil {
			m.err = typed.err.Error()
			return m, nil
		}
		m.populateLists(typed.hosts, typed.secrets, typed.keys, typed.passkeys)
		return m, nil
	case reauthMsg:
		if typed.err != nil {
			m.err = typed.err.Error()
			return m, nil
		}
		m.err = ""
		m.screen = ScreenSecrets
		return m, m.revealSecretCmd(m.pendingSecretName)
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
	case ScreenPasskeys:
		var cmd tea.Cmd
		m.passkeysList, cmd = m.passkeysList.Update(msg)
		return m, cmd
	case ScreenReauth:
		var cmd tea.Cmd
		m.reauthInput, cmd = m.reauthInput.Update(msg)
		return m, cmd
	default:
		var cmd tea.Cmd
		m.hostsList, cmd = m.hostsList.Update(msg)
		return m, cmd
	}
}

func (m Model) loadDataCmd() tea.Cmd {
	return func() tea.Msg {
		return loadData(m.client)
	}
}

func loadData(client Client) tea.Msg {
	hosts, err := client.ListHosts(context.Background())
	if err != nil {
		return loadedMsg{err: err}
	}
	secrets, err := client.ListSecrets(context.Background())
	if err != nil {
		return loadedMsg{err: err}
	}
	keys, err := client.ListKeys(context.Background())
	if err != nil {
		return loadedMsg{err: err}
	}
	passkeys, err := client.ListPasskeys(context.Background())
	if err != nil {
		return loadedMsg{err: err}
	}
	return loadedMsg{
		hosts:    hosts,
		secrets:  secrets,
		keys:     keys,
		passkeys: passkeys,
	}
}

func (m Model) revealSecretCmd(name string) tea.Cmd {
	return func() tea.Msg {
		value, err := m.client.RevealSecret(context.Background(), name)
		return revealedSecretMsg{name: name, value: value, err: err}
	}
}

func (m Model) reauthCmd(passphrase string) tea.Cmd {
	return func() tea.Msg {
		err := m.client.Reauth(context.Background(), passphrase)
		return reauthMsg{err: err}
	}
}

func (m *Model) populateLists(hosts []Host, secrets []Secret, keys []Key, passkeys []Passkey) {
	hostItems := make([]list.Item, 0, len(hosts))
	hostMap := make(map[string]Host, len(hosts))
	for _, host := range hosts {
		description := fmt.Sprintf("%s:%d user=%s", host.Address, host.Port, host.User)
		if len(host.Tags) > 0 {
			description += " tags=" + strings.Join(host.Tags, ",")
		}
		hostItems = append(hostItems, hostItem{
			name:        host.Name,
			description: description,
			tags:        append([]string(nil), host.Tags...),
		})
		hostMap[host.Name] = host
	}
	m.hostsByName = hostMap
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

	passkeyItems := make([]list.Item, 0, len(passkeys))
	for _, passkey := range passkeys {
		passkeyItems = append(passkeyItems, passkeyItem{
			label:       passkey.Label,
			description: fmt.Sprintf("hmac_secret=%t", passkey.SupportsHMACSecret),
		})
	}
	m.passkeysList.SetItems(passkeyItems)
	m.passkeysList.NewStatusMessage("Passkeys loaded")
}

func (m Model) renderHostDetailView() string {
	host, ok := m.hostsByName[m.selectedHostName]
	if !ok {
		return "Host detail unavailable"
	}
	return fmt.Sprintf(
		"Host Detail\n\nName: %s\nAddress: %s\nUser: %s\nPort: %d\nTags: %s\n\nPress ESC to go back.",
		host.Name,
		host.Address,
		host.User,
		host.Port,
		strings.Join(host.Tags, ", "),
	)
}

// clearRevealedSecrets resets all secret descriptions back to hidden
// state, ensuring no revealed values persist when the vault is locked.
func (m *Model) clearRevealedSecrets() {
	items := m.secretsList.Items()
	cleared := make([]list.Item, 0, len(items))
	for _, item := range items {
		secret, ok := item.(secretItem)
		if !ok {
			cleared = append(cleared, item)
			continue
		}
		secret.description = "Press Enter to reveal (re-auth required)"
		cleared = append(cleared, secret)
	}
	m.secretsList.SetItems(cleared)
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
	tags        []string
}

func (i hostItem) Title() string       { return i.name }
func (i hostItem) Description() string { return i.description }
func (i hostItem) FilterValue() string {
	return i.name + " " + i.description + " " + strings.Join(i.tags, " ")
}

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

type passkeyItem struct {
	label       string
	description string
}

func (i passkeyItem) Title() string       { return i.label }
func (i passkeyItem) Description() string { return i.description }
func (i passkeyItem) FilterValue() string { return i.label + " " + i.description }
