package audit

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
)

func TestHashChainAppendAndVerify(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionVaultUnlock,
		TargetType: "vault",
		TargetID:   "vault-1",
		Result:     "success",
		Details: detailPayload{
			Reason: "initial unlock",
		},
	}))
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionSecretCreate,
		TargetType: "secret",
		TargetID:   "db-password",
		Result:     "success",
		Details: detailPayload{
			Reason: "bootstrap",
		},
	}))
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionHostCreate,
		TargetType: "host",
		TargetID:   "prod-bastion",
		Result:     "success",
		Details: detailPayload{
			Reason: "onboarding",
		},
	}))

	verify, err := svc.Verify(ctx)
	require.NoError(t, err)
	require.True(t, verify.Valid)
	require.Equal(t, 3, verify.EventCount)
	require.NotEmpty(t, verify.ChainTip)
}

func TestHashChainTamperMiddleDetailsFails(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	recordThreeEvents(t, ctx, svc)

	events, err := svc.List(ctx, Filter{})
	require.NoError(t, err)
	require.Len(t, events, 3)

	_, err = store.DB().Exec(`UPDATE audit_events SET details_json = ? WHERE id = ?`, `{"reason":"tampered"}`, events[1].ID)
	require.NoError(t, err)

	verify, err := svc.Verify(ctx)
	require.NoError(t, err)
	require.False(t, verify.Valid)
	require.Contains(t, verify.Error, "hash mismatch")
}

func TestHashChainTamperEventHashFails(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	recordThreeEvents(t, ctx, svc)
	events, err := svc.List(ctx, Filter{})
	require.NoError(t, err)
	require.Len(t, events, 3)

	_, err = store.DB().Exec(`UPDATE audit_events SET event_hash = ? WHERE id = ?`, "deadbeef", events[2].ID)
	require.NoError(t, err)

	verify, err := svc.Verify(ctx)
	require.NoError(t, err)
	require.False(t, verify.Valid)
	require.Contains(t, verify.Error, "hash mismatch")
}

func TestHashChainEmptyVerifySucceeds(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	verify, err := svc.Verify(context.Background())
	require.NoError(t, err)
	require.True(t, verify.Valid)
	require.Equal(t, 0, verify.EventCount)
	require.Empty(t, verify.ChainTip)
}

func TestCanonicalJSONStructProducesSortedKeysNoWhitespace(t *testing.T) {
	t.Parallel()

	payload := struct {
		Z string `json:"z"`
		A string `json:"a"`
		M string `json:"m"`
	}{
		Z: "last",
		A: "first",
		M: "middle",
	}

	got, err := canonicalJSON(payload)
	require.NoError(t, err)
	require.JSONEq(t, `{"a":"first","m":"middle","z":"last"}`, string(got))
	require.NotContains(t, string(got), " ")
}

func TestCanonicalJSONDeterministicForSameInput(t *testing.T) {
	t.Parallel()

	payload := detailPayload{
		Reason:  "deterministic",
		Message: "same bytes every time",
	}
	first, err := canonicalJSON(payload)
	require.NoError(t, err)
	second, err := canonicalJSON(payload)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestCanonicalJSONRejectsMapInput(t *testing.T) {
	t.Parallel()

	_, err := canonicalJSON(map[string]string{"a": "b"})
	require.Error(t, err)
}

func TestMutexSerializationConcurrentRecordKeepsValidChain(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	const writes = 100
	var wg sync.WaitGroup
	errCh := make(chan error, writes)
	for i := 0; i < writes; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := svc.Record(ctx, Event{
				Action:     ActionSystemAuthFailure,
				TargetType: "system",
				TargetID:   "auth",
				Result:     "error",
				Details: detailPayload{
					Reason:  "parallel",
					Message: "idx",
				},
				Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Nanosecond),
			})
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	verify, err := svc.Verify(ctx)
	require.NoError(t, err)
	require.True(t, verify.Valid)
	require.Equal(t, writes, verify.EventCount)
}

func TestConcurrentRecordChainTipConsistent(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	const writes = 50
	var wg sync.WaitGroup
	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Record(ctx, Event{
				Action:     ActionSecretReveal,
				TargetType: "secret",
				TargetID:   "api-token",
				Result:     "success",
				Details:    detailPayload{Reason: "chain"},
			})
		}()
	}
	wg.Wait()

	verify, err := svc.Verify(ctx)
	require.NoError(t, err)
	require.True(t, verify.Valid)

	events, err := svc.List(ctx, Filter{})
	require.NoError(t, err)
	require.NotEmpty(t, events)
	require.Equal(t, events[len(events)-1].EventHash, verify.ChainTip)
}

func TestEventRecordingSupportsAllActionTypes(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	for _, action := range AllActionTypes {
		action := action
		require.NoError(t, svc.Record(ctx, Event{
			Action:     action,
			TargetType: "entity",
			TargetID:   action,
			Result:     "success",
			Details: detailPayload{
				Reason: "coverage",
			},
		}))
	}

	for _, action := range AllActionTypes {
		filtered, err := svc.List(ctx, Filter{Action: action})
		require.NoError(t, err)
		require.Len(t, filtered, 1, "action %s should be present exactly once", action)
	}
}

func TestEventRecordingContainsCoreFields(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionSecretCreate,
		TargetType: "secret",
		TargetID:   "webhook",
		Result:     "success",
		Details: detailPayload{
			Reason: "create",
		},
	}))

	events, err := svc.List(ctx, Filter{TargetID: "webhook"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.False(t, events[0].Timestamp.IsZero())
	require.Equal(t, ActionSecretCreate, events[0].Action)
	require.Equal(t, "secret", events[0].TargetType)
	require.Equal(t, "webhook", events[0].TargetID)
	require.Equal(t, "success", events[0].Result)
}

func TestEventRecordingStripsSensitiveFieldsFromDetails(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()

	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionSecretReveal,
		TargetType: "secret",
		TargetID:   "sensitive",
		Result:     "success",
		Details: sensitiveDetails{
			Message:    "ok",
			Secret:     "top-secret",
			Passphrase: "abc123",
			Token:      "xyz",
		},
	}))

	events, err := svc.List(ctx, Filter{TargetID: "sensitive"})
	require.NoError(t, err)
	require.Len(t, events, 1)

	details := events[0].DetailsJSON
	require.NotContains(t, details, "top-secret")
	require.NotContains(t, strings.ToLower(details), "passphrase")
	require.NotContains(t, strings.ToLower(details), "token")
}

func TestAuditListFiltersByActionDateRangeAndTargetID(t *testing.T) {
	t.Parallel()

	store, vmk := newAuditTestStore(t)
	defer vmk.Destroy()

	svc := mustNewService(t, store.Audit)
	ctx := context.Background()
	base := time.Now().UTC().Add(-10 * time.Minute)

	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionHostCreate,
		TargetType: "host",
		TargetID:   "host-a",
		Result:     "success",
		Timestamp:  base,
		Details:    detailPayload{Reason: "old"},
	}))
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionHostDelete,
		TargetType: "host",
		TargetID:   "host-b",
		Result:     "success",
		Timestamp:  base.Add(2 * time.Minute),
		Details:    detailPayload{Reason: "mid"},
	}))
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionHostCreate,
		TargetType: "host",
		TargetID:   "host-c",
		Result:     "success",
		Timestamp:  base.Add(4 * time.Minute),
		Details:    detailPayload{Reason: "new"},
	}))

	byAction, err := svc.List(ctx, Filter{Action: ActionHostCreate})
	require.NoError(t, err)
	require.Len(t, byAction, 2)

	since := base.Add(90 * time.Second)
	until := base.Add(3 * time.Minute)
	byRange, err := svc.List(ctx, Filter{Since: &since, Until: &until})
	require.NoError(t, err)
	require.Len(t, byRange, 1)
	require.Equal(t, "host-b", byRange[0].TargetID)

	byTarget, err := svc.List(ctx, Filter{TargetID: "host-c"})
	require.NoError(t, err)
	require.Len(t, byTarget, 1)
	require.Equal(t, ActionHostCreate, byTarget[0].Action)
}

type detailPayload struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type sensitiveDetails struct {
	Message    string `json:"message,omitempty"`
	Secret     string `json:"secret,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Token      string `json:"token,omitempty"`
}

func mustNewService(t *testing.T, repo storage.AuditRepository) *Service {
	t.Helper()
	svc, err := NewService(repo)
	require.NoError(t, err)
	return svc
}

func recordThreeEvents(t *testing.T, ctx context.Context, svc *Service) {
	t.Helper()
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionVaultUnlock,
		TargetType: "vault",
		TargetID:   "vault-1",
		Result:     "success",
		Details:    detailPayload{Reason: "one"},
	}))
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionSecretReveal,
		TargetType: "secret",
		TargetID:   "secret-1",
		Result:     "success",
		Details:    detailPayload{Reason: "two"},
	}))
	require.NoError(t, svc.Record(ctx, Event{
		Action:     ActionKeyRotate,
		TargetType: "identity",
		TargetID:   "identity-1",
		Result:     "success",
		Details:    detailPayload{Reason: "three"},
	}))
}

func newAuditTestStore(t *testing.T) (*storage.Store, *memguard.LockedBuffer) {
	t.Helper()
	path := t.TempDir() + "/vault.db"
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)

	vc := crypto.NewVaultCrypto(vmk, "audit-test-vault")
	store, err := storage.Open(path, "audit-test-vault", vc)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store, vmk
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.Exec(query, args...)
	require.NoError(t, err)
}
