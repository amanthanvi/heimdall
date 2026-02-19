package app

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/amanthanvi/heimdall/internal/storage"
)

var (
	hostNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
	hostAddressPattern = regexp.MustCompile(`^[a-zA-Z0-9._:%-]{1,253}$`)
	sshUserPattern     = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

type HostService struct {
	hosts    storage.HostRepository
	sessions storage.SessionRepository
}

func NewHostService(hosts storage.HostRepository, sessions storage.SessionRepository) *HostService {
	return &HostService{
		hosts:    hosts,
		sessions: sessions,
	}
}

func (s *HostService) Create(ctx context.Context, req CreateHostRequest) (*storage.Host, error) {
	if err := validateHostInputs(req.Name, req.Address, req.User, req.Port); err != nil {
		return nil, err
	}
	if req.Port == 0 {
		req.Port = 22
	}

	tags := append([]string(nil), req.Tags...)
	if req.Group != "" {
		tags = append(tags, "group:"+req.Group)
	}
	host := &storage.Host{
		Name:    req.Name,
		Address: req.Address,
		Port:    req.Port,
		User:    req.User,
		Tags:    dedupeStrings(tags),
		EnvRefs: cloneStringMap(req.EnvRefs),
	}
	if err := s.hosts.Create(ctx, host); err != nil {
		if isDuplicateError(err) {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateName, req.Name)
		}
		return nil, fmt.Errorf("create host: %w", err)
	}
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
	if req.EnvRefs != nil {
		host.EnvRefs = cloneStringMap(req.EnvRefs)
	}

	if err := validateHostInputs(host.Name, host.Address, host.User, host.Port); err != nil {
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
	return nil
}

func (s *HostService) List(ctx context.Context, req ListHostsRequest) ([]storage.Host, error) {
	hosts, err := s.hosts.List(ctx, storage.HostFilter{Tag: req.Tag})
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}

	filtered := make([]storage.Host, 0, len(hosts))
	for _, host := range hosts {
		if req.Group != "" && !hostMatchesGroup(host, req.Group) {
			continue
		}
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

func (s *HostService) Import(ctx context.Context, sshConfigPath string) ([]storage.Host, []ImportWarning, error) {
	file, err := os.Open(sshConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("import ssh config: open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	type pendingHost struct {
		name        string
		address     string
		user        string
		port        int
		proxyJump   string
		identityRef string
	}

	var (
		warnings []ImportWarning
		imported []storage.Host
		current  pendingHost
	)
	flushCurrent := func() {
		if current.name == "" || current.address == "" {
			current = pendingHost{}
			return
		}
		envRefs := map[string]string{}
		if current.proxyJump != "" {
			envRefs["proxy_jump"] = current.proxyJump
		}
		if current.identityRef != "" {
			envRefs["identity_ref"] = current.identityRef
		}

		host, createErr := s.Create(ctx, CreateHostRequest{
			Name:    current.name,
			Address: current.address,
			User:    current.user,
			Port:    current.port,
			EnvRefs: envRefs,
		})
		if createErr != nil {
			warnings = append(warnings, ImportWarning{
				Message: fmt.Sprintf("skip host %s: %v", current.name, createErr),
			})
			current = pendingHost{}
			return
		}
		imported = append(imported, *host)
		current = pendingHost{}
	}

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")

		switch key {
		case "host":
			flushCurrent()
			if strings.ContainsAny(value, "*?") {
				warnings = append(warnings, ImportWarning{
					Line:    lineNo,
					Message: "wildcard Host entries are skipped",
				})
				continue
			}
			current.name = value
		case "hostname":
			current.address = value
		case "user":
			current.user = value
		case "proxyjump":
			current.proxyJump = value
		case "identityfile":
			current.identityRef = value
		case "port":
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil {
				warnings = append(warnings, ImportWarning{
					Line:    lineNo,
					Message: fmt.Sprintf("invalid port %q", value),
				})
				continue
			}
			current.port = parsed
		case "match", "include":
			warnings = append(warnings, ImportWarning{
				Line:    lineNo,
				Message: fmt.Sprintf("%s directive skipped", key),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("import ssh config: read: %w", err)
	}

	flushCurrent()
	return imported, warnings, nil
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

func hostMatchesGroup(host storage.Host, group string) bool {
	want := strings.ToLower(strings.TrimSpace(group))
	for _, tag := range host.Tags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		if normalized == want || normalized == "group:"+want {
			return true
		}
	}
	return false
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

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func isDuplicateError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}
