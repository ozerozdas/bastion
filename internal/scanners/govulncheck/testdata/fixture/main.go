// Command fixture is the reachability fixture for #37: it calls one vulnerable
// function and leaves another vulnerable package unused.
//
// golang.org/x/net/html.Parse is called, so its advisories are symbol-level
// (reachable). golang.org/x/net/idna is imported and constructed but its
// vulnerable ToASCII/ToUnicode are never called, so its advisories stay at
// package level (unreachable).
package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/idna"
)

func main() {
	doc, err := html.Parse(strings.NewReader("<p>hi</p>"))
	fmt.Println(doc, err, idna.New())
}
