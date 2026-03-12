package app

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/amanthanvi/heimdall/internal/storage"
)

var (
	hostNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
	hostAddressPattern = regexp.MustCompile(`^[a-zA-Z0-9._:%-]{1,253}$`)
	sshUserPattern     = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

type HostService struct {
	hosts          storage.HostRepository
	sessions       storage.SessionRepository
	postMutateHook []func(context.Context) error
}

func NewHostService(hosts storage.HostRepository, sessions storage.SessionRepository, postMutateHook ...func(context.Context) error) *HostService {
	return &HostService{
		hosts:          hosts,
		sessions:       sessions,
		postMutateHook: append([]func(context.Context) error(nil), postMutateHook...),
	}
}

func (s *HostService) Create(ctx context.Context, req CreateHostRequest) (*storage.Host, error) {
	if err := validateHostInputs(req.Name, req.Address, req.User, req.Port); err != nil {
		return nil, err
	}
	if req.Port == 0 {
		req.Port = 22
	}
	keyName := strings.TrimSpace(req.KeyName)
	identityFile := strings.TrimSpace(req.IdentityFile)
	proxyJump := strings.TrimSpace(req.ProxyJump)
	if err := validateHostConnectDefaults(keyName, identityFile, proxyJump); err != nil {
		return nil, err
	}
	knownHostsPolicy, err := normalizeKnownHostsPolicy(req.KnownHostsPolicy)
	if err != nil {
		return nil, err
	}

	host := &storage.Host{
		Name:             req.Name,
		Address:          req.Address,
		Port:             req.Port,
		User:             req.User,
		Notes:            strings.TrimSpace(req.Notes),
		KeyName:          keyName,
		IdentityFile:     identityFile,
		ProxyJump:        proxyJump,
		KnownHostsPolicy: knownHostsPolicy,
		ForwardAgent:     req.ForwardAgent,
		Tags:             dedupeStrings(req.Tags),
	}
	if err := s.hosts.Create(ctx, host); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, req.Name)
		}
		return nil, fmt.Errorf("create host: %w", err)
	}
	s.runPostMutateHooks(ctx)
	return host, nil
}

func (s *HostService) Get(ctx context.Context, name string) (*storage.Host, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: host name is required", ErrValidation)
	}

	host, err := s.hosts.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
	}
	return host, nil
}

func (s *HostService) Update(ctx context.Context, req UpdateHostRequest) (*storage.Host, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return nil, fmt.Errorf("%w: host name is required", ErrValidation)
	}

	host, err := s.hosts.Get(ctx, req.Name)
	if err != nil {
		return nil, fmt.Errorf("update host: load existing host: %w", err)
	}

	if nextName := strings.TrimSpace(req.NewName); nextName != "" {
		host.Name = nextName
	}
	if req.Address != nil {
		host.Address = strings.TrimSpace(*req.Address)
	}
	if req.Port != nil {
		host.Port = *req.Port
	}
	if req.User != nil {
		host.User = strings.TrimSpace(*req.User)
	}
	if req.Tags != nil {
		host.Tags = dedupeStrings(*req.Tags)
	}
	if req.ClearNotes {
		host.Notes = ""
	} else if req.Notes != nil {
		host.Notes = strings.TrimSpace(*req.Notes)
	}
	if req.KeyName != nil {
		host.KeyName = strings.TrimSpace(*req.KeyName)
	}
	if req.IdentityFile != nil {
		host.IdentityFile = strings.TrimSpace(*req.IdentityFile)
	}
	if req.ProxyJump != nil {
		host.ProxyJump = strings.TrimSpace(*req.ProxyJump)
	}
	if req.ClearKnownHostsPolicy {
		host.KnownHostsPolicy = ""
	} else if req.KnownHostsPolicy != nil {
		host.KnownHostsPolicy = strings.TrimSpace(*req.KnownHostsPolicy)
	}
	if req.ForwardAgent != nil {
		host.ForwardAgent = *req.ForwardAgent
	}

	if err := validateHostInputs(host.Name, host.Address, host.User, host.Port); err != nil {
		return nil, err
	}
	if err := validateHostConnectDefaults(host.KeyName, host.IdentityFile, host.ProxyJump); err != nil {
		return nil, err
	}
	if _, err := normalizeKnownHostsPolicy(host.KnownHostsPolicy); err != nil {
		return nil, err
	}
	if host.Port == 0 {
		host.Port = 22
	}

	if err := s.hosts.Update(ctx, host); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, host.Name)
		}
		return nil, fmt.Errorf("update host: %w", err)
	}
	s.runPostMutateHooks(ctx)
	return host, nil
}

func (s *HostService) Delete(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: host name is required", ErrValidation)
	}
	if err := s.hosts.Delete(ctx, name); err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	s.runPostMutateHooks(ctx)
	return nil
}

func (s *HostService) List(ctx context.Context, req ListHostsRequest) ([]storage.Host, error) {
	hosts, err := s.hosts.List(ctx, storage.HostFilter{Tag: req.Tag})
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}

	filtered := make([]storage.Host, 0, len(hosts))
	for _, host := range hosts {
		if req.Search != "" && !hostMatchesSearch(host, req.Search) {
			continue
		}
		filtered = append(filtered, host)
	}

	switch req.SortBy {
	case "", SortByName:
		sort.SliceStable(filtered, func(i, j int) bool {
			return filtered[i].Name < filtered[j].Name
		})
		return filtered, nil
	case SortByLastConnected:
		return s.sortByLastConnected(ctx, filtered)
	default:
		return nil, fmt.Errorf("%w: unsupported host sort mode %q", ErrValidation, req.SortBy)
	}
}

func (s *HostService) sortByLastConnected(ctx context.Context, hosts []storage.Host) ([]storage.Host, error) {
	withTimes := make([]hostWithLastConnected, 0, len(hosts))
	for _, host := range hosts {
		entry := hostWithLastConnected{host: host}
		sessions, err := s.sessions.ListByHostID(ctx, host.ID)
		if err != nil {
			return nil, fmt.Errorf("list sessions for host %s: %w", host.Name, err)
		}
		for _, session := range sessions {
			if session.StartedAt.After(entry.lastConnected) {
				entry.lastConnected = session.StartedAt
			}
		}
		withTimes = append(withTimes, entry)
	}

	sort.SliceStable(withTimes, func(i, j int) bool {
		return withTimes[i].lastConnected.After(withTimes[j].lastConnected)
	})

	sorted := make([]storage.Host, 0, len(withTimes))
	for _, entry := range withTimes {
		sorted = append(sorted, entry.host)
	}
	return sorted, nil
}

func hostMatchesSearch(host storage.Host, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(host.Name), query) {
		return true
	}
	if strings.Contains(strings.ToLower(host.Address), query) {
		return true
	}
	if strings.Contains(strings.ToLower(host.User), query) {
		return true
	}
	for _, tag := range host.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

func (s *HostService) runPostMutateHooks(ctx context.Context) {
	for _, hook := range s.postMutateHook {
		if hook == nil {
			continue
		}
		_ = hook(ctx)
	}
}

func validateHostInputs(name, address, user string, port int) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: host name is required", ErrValidation)
	}
	if !hostNamePattern.MatchString(name) {
		return fmt.Errorf("%w: host name format is invalid", ErrValidation)
	}

	address = strings.TrimSpace(address)
	if address == "" {
		return fmt.Errorf("%w: host address is required", ErrValidation)
	}
	if strings.HasPrefix(address, "-") || !hostAddressPattern.MatchString(address) {
		return fmt.Errorf("%w: host address contains invalid characters", ErrValidation)
	}

	user = strings.TrimSpace(user)
	if user != "" && (strings.HasPrefix(user, "-") || !sshUserPattern.MatchString(user)) {
		return fmt.Errorf("%w: user contains invalid characters", ErrValidation)
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("%w: host port must be 1-65535", ErrValidation)
	}
	return nil
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func validateHostConnectDefaults(keyName, identityFile, proxyJump string) error {
	if keyName != "" && identityFile != "" {
		return fmt.Errorf("%w: host defaults cannot set both key_name and identity_file", ErrValidation)
	}
	if keyName != "" && !hostNamePattern.MatchString(keyName) {
		return fmt.Errorf("%w: key_name format is invalid", ErrValidation)
	}
	if strings.HasPrefix(identityFile, "-") {
		return fmt.Errorf("%w: identity_file contains invalid characters", ErrValidation)
	}
	if strings.HasPrefix(proxyJump, "-") {
		return fmt.Errorf("%w: proxy_jump contains invalid characters", ErrValidation)
	}
	return nil
}

func normalizeKnownHostsPolicy(raw string) (string, error) {
	policy := strings.ToLower(strings.TrimSpace(raw))
	switch policy {
	case "", "tofu", "accept-new", "strict", "off":
		return policy, nil
	default:
		return "", fmt.Errorf("%w: unsupported known_hosts_policy %q", ErrValidation, raw)
	}
}

func isDuplicateError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}
