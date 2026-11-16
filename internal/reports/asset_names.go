package reports

import (
	"context"
	"fmt"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// AssetNames maps every non-archived asset id to its display name. The findings
// export uses it to name the project column; archived assets are absent because
// their findings are absent from the latest-findings list too.
func (s *Service) AssetNames(ctx context.Context) (map[int64]string, error) {
	rows, err := sqlcdb.New(s.db).ListAssets(ctx)
	if err != nil {
		return nil, fmt.Errorf("reports: list asset names: %w", err)
	}
	names := make(map[int64]string, len(rows))
	for _, row := range rows {
		names[row.ID] = row.DisplayName
	}
	return names, nil
}
