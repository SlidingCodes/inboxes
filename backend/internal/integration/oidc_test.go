//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/inboxes/backend/internal/store"
)

// TestOIDC_FirstLoginBootstrapsOwner covers the case config_test.go and the
// handler unit tests can't: the very first OIDC login on a fresh instance
// has no org to join yet, so it must create one and become its owner/admin.
func TestOIDC_FirstLoginBootstrapsOwner(t *testing.T) {
	ctx := context.Background()
	truncateAll(ctx)

	userID, orgID, role, err := testStore.GetOrCreateOIDCUser(ctx, "first@example.com", "First User")
	if err != nil {
		t.Fatalf("GetOrCreateOIDCUser: %v", err)
	}
	if userID == "" || orgID == "" {
		t.Fatalf("GetOrCreateOIDCUser: empty userID=%q orgID=%q", userID, orgID)
	}
	if role != "admin" {
		t.Errorf("role = %q, want admin (first user owns the instance)", role)
	}
}

// TestOIDC_SecondLoginJoinsExistingOrg covers the steady-state case: once an
// org exists, a new identity joins it as a member instead of bootstrapping
// a second org (self-hosted is single-org).
func TestOIDC_SecondLoginJoinsExistingOrg(t *testing.T) {
	ctx := context.Background()
	truncateAll(ctx)

	_, firstOrgID, _, err := testStore.GetOrCreateOIDCUser(ctx, "first@example.com", "First User")
	if err != nil {
		t.Fatalf("GetOrCreateOIDCUser (first): %v", err)
	}

	_, secondOrgID, role, err := testStore.GetOrCreateOIDCUser(ctx, "second@example.com", "Second User")
	if err != nil {
		t.Fatalf("GetOrCreateOIDCUser (second): %v", err)
	}
	if secondOrgID != firstOrgID {
		t.Errorf("second user org = %q, want %q (same self-hosted org)", secondOrgID, firstOrgID)
	}
	if role != "member" {
		t.Errorf("role = %q, want member", role)
	}
}

// TestOIDC_SameEmailLogsInToSameUser covers repeat logins: the same email
// must resolve to the same user row, not create a duplicate.
func TestOIDC_SameEmailLogsInToSameUser(t *testing.T) {
	ctx := context.Background()
	truncateAll(ctx)

	userID1, _, _, err := testStore.GetOrCreateOIDCUser(ctx, "repeat@example.com", "Repeat User")
	if err != nil {
		t.Fatalf("GetOrCreateOIDCUser (1st login): %v", err)
	}
	userID2, _, _, err := testStore.GetOrCreateOIDCUser(ctx, "repeat@example.com", "Repeat User")
	if err != nil {
		t.Fatalf("GetOrCreateOIDCUser (2nd login): %v", err)
	}
	if userID1 != userID2 {
		t.Errorf("userID changed across logins: %q then %q", userID1, userID2)
	}
}

// TestOIDC_ActivatesInvitedUser covers the handoff from the old invite flow:
// an admin can still invite a teammate by email, and that placeholder row
// activates on the invitee's first OIDC login instead of staying stuck
// waiting for a claim link that OIDC-only mode no longer sends.
func TestOIDC_ActivatesInvitedUser(t *testing.T) {
	ctx := context.Background()
	truncateAll(ctx)

	adminID, orgID, err := testStore.CreateOrgAndAdmin(ctx, "Test Org", "admin@example.com", "Admin", "", true, true)
	if err != nil {
		t.Fatalf("CreateOrgAndAdmin: %v", err)
	}
	_ = adminID

	var placeholderID string
	err = testStore.WithTx(ctx, func(tx store.Store) error {
		return tx.Q().QueryRow(ctx,
			`INSERT INTO users (org_id, email, name, role, status) VALUES ($1, $2, $3, 'member', 'invited') RETURNING id`,
			orgID, "invitee@example.com", "",
		).Scan(&placeholderID)
	})
	if err != nil {
		t.Fatalf("insert placeholder user: %v", err)
	}

	userID, gotOrgID, role, err := testStore.GetOrCreateOIDCUser(ctx, "invitee@example.com", "Invitee")
	if err != nil {
		t.Fatalf("GetOrCreateOIDCUser: %v", err)
	}
	if userID != placeholderID {
		t.Errorf("userID = %q, want the pre-existing invited user %q", userID, placeholderID)
	}
	if gotOrgID != orgID {
		t.Errorf("orgID = %q, want %q", gotOrgID, orgID)
	}
	if role != "member" {
		t.Errorf("role = %q, want member (unchanged from the invite)", role)
	}

	var status string
	if err := testStore.Q().QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, userID).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "active" {
		t.Errorf("status = %q, want active", status)
	}
}
