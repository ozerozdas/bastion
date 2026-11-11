package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// AssetTarget is the stored target information a scan resolver needs: the
// asset's canonical ref, the connection its scans authenticate with and the
// branch a repository tracks.
type AssetTarget struct {
	ID            int64
	Kind          string
	Ref           string
	ConnectionID  int64
	DefaultBranch string
}

// LoadAssetTarget reads one asset's target information. A missing asset is an
// error: a scan queued for it can no longer resolve.
func LoadAssetTarget(ctx context.Context, db *sql.DB, id int64) (AssetTarget, error) {
	if db == nil {
		return AssetTarget{}, errors.New("store: load asset target: database is required")
	}
	row, err := sqlcdb.New(db).GetAsset(ctx, id)
	if err != nil {
		return AssetTarget{}, fmt.Errorf("store: load asset target %d: %w", id, err)
	}
	return assetTarget(row), nil
}

// RepoAssetTarget reads the repo asset with this owner/name ref, so a source
// can pick the token of the connection that owns the repository. found is
// false when no such asset exists (a CLI scan of an unrecorded repo).
func RepoAssetTarget(ctx context.Context, db *sql.DB, fullName string) (target AssetTarget, found bool, err error) {
	if db == nil {
		return AssetTarget{}, false, errors.New("store: load repo asset: database is required")
	}
	row, err := sqlcdb.New(db).GetAssetByKindRef(ctx, sqlcdb.GetAssetByKindRefParams{
		Kind: string(findings.AssetKindRepo),
		Ref:  fullName,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return AssetTarget{}, false, nil
	}
	if err != nil {
		return AssetTarget{}, false, fmt.Errorf("store: load repo asset %q: %w", fullName, err)
	}
	return assetTarget(row), true, nil
}

// assetTarget copies the resolver's view out of an assets row.
func assetTarget(row sqlcdb.Asset) AssetTarget {
	target := AssetTarget{
		ID:            row.ID,
		Kind:          row.Kind,
		Ref:           row.Ref,
		DefaultBranch: row.DefaultBranch.String,
	}
	if row.ConnectionID.Valid {
		target.ConnectionID = row.ConnectionID.Int64
	}
	return target
}
