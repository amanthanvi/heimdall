package grpc

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"google.golang.org/grpc/metadata"
)

const (
	defaultReauthTTL = 60 * time.Second

	defaultTier0LimitPerMinute = 1000
	defaultTier1LimitPerMinute = 100
	defaultTier2LimitPerMinute = 10

	callerPIDMetadataKey       = "x-heimdall-pid"
	callerStartTimeMetadataKey = "x-heimdall-process-start"
)

type authTier int

const (
	tier0 authTier = iota
	tier1
	tier2
)

type daemonState interface {
	IsLocked() bool
	HasLiveVMK() bool
	Unlock(passphrase []byte) error
	Lock() error
	LastPeerPID() int
	RegisterSigningSession(id string)
}

type callerIdentity struct {
	pid      int
	startKey string
}

func (c callerIdentity) key() string {
	return fmt.Sprintf("%d@%s", c.pid, c.startKey)
}

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now().UTC()
}

func methodTier(fullMethod string) authTier {
	switch fullMethod {
	case v1.VaultService_Status_FullMethodName,
		v1.VaultService_Unlock_FullMethodName,
		v1.VaultService_Lock_FullMethodName,
		v1.VersionService_GetVersion_FullMethodName:
		return tier0
	case v1.SecretService_GetSecretValue_FullMethodName,
		v1.SecretService_DeleteSecret_FullMethodName,
		v1.KeyService_ExportKey_FullMethodName:
		return tier2
	default:
		return tier1
	}
}

func tierLimitPerMinute(tier authTier) int {
	switch tier {
	case tier0:
		return defaultTier0LimitPerMinute
	case tier2:
		return defaultTier2LimitPerMinute
	default:
		return defaultTier1LimitPerMinute
	}
}

func callerFromContext(ctx context.Context, d daemonState) callerIdentity {
	caller := callerIdentity{
		pid:      0,
		startKey: "unknown",
	}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(callerPIDMetadataKey); len(values) > 0 {
			pid, err := strconv.Atoi(strings.TrimSpace(values[0]))
			if err == nil && pid > 0 {
				caller.pid = pid
			}
		}
		if values := md.Get(callerStartTimeMetadataKey); len(values) > 0 {
			start := strings.TrimSpace(values[0])
			if start != "" {
				caller.startKey = start
			}
		}
	}

	if caller.pid <= 0 && d != nil {
		if pid := d.LastPeerPID(); pid > 0 {
			caller.pid = pid
		}
	}
	if caller.pid <= 0 {
		caller.pid = os.Getpid()
	}

	return caller
}
