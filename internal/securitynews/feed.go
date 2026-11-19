package securitynews

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetch downloads one source and maps it to safe items.
func (s *Service) fetch(ctx context.Context, source Source) ([]Item, string) {
	url := s.urls[source.ID]
	if url == "" {
		return nil, "no feed URL for this source"
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "could not build the request"
	}
	request.Header.Set("User-Agent", s.agent)
	request.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, "could not reach the feed"
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Sprintf("the feed answered %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return nil, "could not read the feed"
	}
	if len(body) > maxFeedBytes {
		return nil, "the feed is larger than the allowed size"
	}

	parsed, err := parseFeed(body)
	if err != nil {
		s.log.Debug("parse security feed", "source", source.ID, "error", err)
		return nil, "the feed is not valid RSS or Atom"
	}

	items := make([]Item, 0, len(parsed))
	for _, entry := range parsed {
		item := Item{
			Title:     plainText(entry.Title, MaxTitleRunes),
			Source:    source.Name,
			SourceID:  source.ID,
			Published: entry.Published,
			Link:      safeLink(entry.Link),
			Summary:   plainText(entry.Summary, MaxSummaryRunes),
		}
		if item.Title == "" || item.Link == "" {
			continue
		}
		items = append(items, item)
	}
	return items, ""
}

// rawItem is a parsed feed entry, before sanitization.
type rawItem struct {
	Title     string
	Link      string
	Published time.Time
	Summary   string
}

// rssDocument covers RSS 2.0, the format most security vendors publish.
type rssDocument struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
			Date        string `xml:"date"` // dc:date
			GUID        string `xml:"guid"`
		} `xml:"item"`
	} `xml:"channel"`
}

// atomDocument covers Atom 1.0 (Reddit and several vendor blogs).
type atomDocument struct {
	XMLName xml.Name    `xml:"feed"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title     string     `xml:"title"`
	Links     []atomLink `xml:"link"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
	Summary   string     `xml:"summary"`
	Content   string     `xml:"content"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Type string `xml:"type,attr"`
}

// parseFeed accepts RSS 2.0 and Atom. A document that parses as neither fails
// so the source reports one isolated error.
func parseFeed(body []byte) ([]rawItem, error) {
	var rss rssDocument
	if err := xml.Unmarshal(body, &rss); err == nil && len(rss.Channel.Items) > 0 {
		items := make([]rawItem, 0, len(rss.Channel.Items))
		for _, entry := range rss.Channel.Items {
			link := strings.TrimSpace(entry.Link)
			if link == "" {
				link = strings.TrimSpace(entry.GUID)
			}
			date := entry.PubDate
			if strings.TrimSpace(date) == "" {
				date = entry.Date
			}
			items = append(items, rawItem{
				Title:     entry.Title,
				Link:      link,
				Published: parsePublished(date),
				Summary:   entry.Description,
			})
		}
		return items, nil
	}

	var atom atomDocument
	if err := xml.Unmarshal(body, &atom); err == nil && len(atom.Entries) > 0 {
		items := make([]rawItem, 0, len(atom.Entries))
		for _, entry := range atom.Entries {
			summary := entry.Summary
			if strings.TrimSpace(summary) == "" {
				summary = entry.Content
			}
			date := entry.Published
			if strings.TrimSpace(date) == "" {
				date = entry.Updated
			}
			items = append(items, rawItem{
				Title:     entry.Title,
				Link:      atomEntryLink(entry.Links),
				Published: parsePublished(date),
				Summary:   summary,
			})
		}
		return items, nil
	}

	return nil, errors.New("no RSS items or Atom entries")
}

// atomEntryLink picks the entry's human-facing link, falling back to the
// first absolute link when no alternate is declared.
func atomEntryLink(links []atomLink) string {
	var fallback string
	for _, link := range links {
		if fallback == "" {
			fallback = link.Href
		}
		if (link.Rel == "" || link.Rel == "alternate") &&
			(link.Type == "" || link.Type == "text/html") {
			return link.Href
		}
	}
	return fallback
}

// publishedLayouts are the date layouts RSS and Atom feeds use in practice.
// An unparsable date is not fatal: the item is kept with a zero time and sorts
// last.
var publishedLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	time.RFC1123Z,
	time.RFC1123,
	time.RFC822Z,
	time.RFC822,
	"Mon, 2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05 -0700",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05-0700",
}

func parsePublished(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range publishedLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
