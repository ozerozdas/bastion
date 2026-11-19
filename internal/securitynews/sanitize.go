package securitynews

import (
	"html"
	"net/url"
	"strings"
)

// plainText turns feed markup into one short plain-text line. Feed descriptions
// are HTML, often escaped twice (XML then HTML entities), so the markup strip
// runs before and after entity decoding. An agent or the UI never sees a tag.
func plainText(value string, limit int) string {
	value = stripHTML(value)
	value = html.UnescapeString(value)
	value = stripHTML(value)
	value = strings.Join(strings.Fields(value), " ")
	return clipRunes(strings.TrimSpace(value), limit)
}

// stripHTML removes tags and the contents of script and style elements. It is
// deliberately small and linear: the input is capped by maxFeedBytes.
func stripHTML(value string) string {
	var out strings.Builder
	skip := ""
	for index := 0; index < len(value); {
		if value[index] != '<' {
			if skip == "" {
				out.WriteByte(value[index])
			}
			index++
			continue
		}
		end := strings.IndexByte(value[index:], '>')
		if end < 0 {
			// An unterminated tag is dropped rather than leaked as text.
			break
		}
		tag := value[index+1 : index+end]
		name, closing := tagName(tag)
		index += end + 1

		if skip != "" {
			if closing && name == skip {
				skip = ""
				out.WriteByte(' ')
			}
			continue
		}
		if !closing && (name == "script" || name == "style") {
			skip = name
			continue
		}
		// Every tag becomes a word break, so "<p>a</p><p>b</p>" is "a b".
		out.WriteByte(' ')
	}
	return out.String()
}

// tagName reads a tag's lower-case element name and whether it closes.
func tagName(tag string) (string, bool) {
	tag = strings.TrimSpace(tag)
	closing := strings.HasPrefix(tag, "/")
	if closing {
		tag = strings.TrimSpace(tag[1:])
	}
	for index, char := range tag {
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' || char == '/' {
			return strings.ToLower(tag[:index]), closing
		}
	}
	return strings.ToLower(tag), closing
}

// clipRunes cuts value to limit characters, appending an ASCII marker when it
// does. ASCII keeps the marker unambiguous in every locale.
func clipRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	const marker = "..."
	if limit <= len(marker) {
		return string(runes[:limit])
	}
	return string(runes[:limit-len(marker)]) + marker
}

// safeLink accepts only absolute http(s) links, so a feed cannot hand the UI a
// javascript:, data: or file: URL.
func safeLink(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.Host == "" {
		return ""
	}
	return parsed.String()
}
