package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Trend window bounds, in days ending today.
const (
	// DefaultTrendDays is the window when the caller does not ask for one.
	DefaultTrendDays = 90
	// MaxTrendDays caps the window, so one request cannot ask for years.
	MaxTrendDays = 365
)

// TrendPoint is one scanned day of an asset: the open findings of that day's
// last succeeded scan, per effective severity.
type TrendPoint struct {
	// Date is the day, as YYYY-MM-DD.
	Date     string
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// TrendSeries is one asset's points, oldest day first.
type TrendSeries struct {
	AssetID     int64
	DisplayName string
	Points      []TrendPoint
}

// Trend reports the open findings of each asset per scanned day in the window.
// A day's point comes from that day's last succeeded scan; days without one
// have no point. The scope is the findings list's: non-archived assets, open
// findings only, ignore decisions applied to every scan, and licence "allow"
// findings hidden. days must be 1..MaxTrendDays; the caller applies
// DefaultTrendDays when the request omitted it.
func (s *Service) Trend(ctx context.Context, assetID int64, days int) ([]TrendSeries, error) {
	if err := (Filter{AssetID: assetID}).validate(); err != nil {
		return nil, err
	}
	if days < 1 || days > MaxTrendDays {
		return nil, fmt.Errorf("%w: days must be between 1 and %d", ErrInvalid, MaxTrendDays)
	}

	since := s.now().UTC().AddDate(0, 0, -(days - 1)).Format(time.DateOnly)
	params := sqlcdb.ReportSeverityTrendParams{Since: since, Now: s.expiryNow()}
	if assetID > 0 {
		params.AssetID = assetID
	}
	rows, err := sqlcdb.New(s.db).ReportSeverityTrend(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("reports: trend: %w", err)
	}

	series := make([]TrendSeries, 0)
	for _, row := range rows {
		if len(series) == 0 || series[len(series)-1].AssetID != row.AssetID {
			series = append(series, TrendSeries{
				AssetID:     row.AssetID,
				DisplayName: row.DisplayName,
				Points:      make([]TrendPoint, 0),
			})
		}
		current := &series[len(series)-1]
		current.Points = append(current.Points, TrendPoint{
			Date:     row.ScanDate,
			Critical: int(row.Critical),
			High:     int(row.High),
			Medium:   int(row.Medium),
			Low:      int(row.Low),
			Unknown:  int(row.Unknown),
		})
	}
	return series, nil
}
