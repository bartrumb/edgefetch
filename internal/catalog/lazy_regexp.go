package catalog

import (
	"regexp"
	"sync"
)

type lazyRegexp struct {
	once sync.Once
	pat  string
	rx   *regexp.Regexp
}

func newLazyRegexp(pat string) *lazyRegexp {
	return &lazyRegexp{pat: pat}
}

func (l *lazyRegexp) get() *regexp.Regexp {
	l.once.Do(func() {
		l.rx = regexp.MustCompile(l.pat)
	})
	return l.rx
}

func (l *lazyRegexp) Match(b []byte) bool                  { return l.get().Match(b) }
func (l *lazyRegexp) MatchString(s string) bool            { return l.get().MatchString(s) }
func (l *lazyRegexp) Find(b []byte) []byte                 { return l.get().Find(b) }
func (l *lazyRegexp) FindIndex(b []byte) []int             { return l.get().FindIndex(b) }
func (l *lazyRegexp) FindString(s string) string           { return l.get().FindString(s) }
func (l *lazyRegexp) FindStringIndex(s string) []int       { return l.get().FindStringIndex(s) }
func (l *lazyRegexp) FindStringSubmatch(s string) []string { return l.get().FindStringSubmatch(s) }
func (l *lazyRegexp) FindStringSubmatchIndex(s string) []int {
	return l.get().FindStringSubmatchIndex(s)
}
func (l *lazyRegexp) FindSubmatch(b []byte) [][]byte       { return l.get().FindSubmatch(b) }
func (l *lazyRegexp) FindSubmatchIndex(b []byte) []int     { return l.get().FindSubmatchIndex(b) }
func (l *lazyRegexp) FindAll(b []byte, n int) [][]byte     { return l.get().FindAll(b, n) }
func (l *lazyRegexp) FindAllIndex(b []byte, n int) [][]int { return l.get().FindAllIndex(b, n) }
func (l *lazyRegexp) FindAllSubmatch(b []byte, n int) [][][]byte {
	return l.get().FindAllSubmatch(b, n)
}
func (l *lazyRegexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	return l.get().FindAllSubmatchIndex(b, n)
}
func (l *lazyRegexp) FindAllString(s string, n int) []string { return l.get().FindAllString(s, n) }
func (l *lazyRegexp) FindAllStringIndex(s string, n int) [][]int {
	return l.get().FindAllStringIndex(s, n)
}
func (l *lazyRegexp) FindAllStringSubmatch(s string, n int) [][]string {
	return l.get().FindAllStringSubmatch(s, n)
}
func (l *lazyRegexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return l.get().FindAllStringSubmatchIndex(s, n)
}
func (l *lazyRegexp) ReplaceAll(src, repl []byte) []byte { return l.get().ReplaceAll(src, repl) }
func (l *lazyRegexp) ReplaceAllLiteral(src, repl []byte) []byte {
	return l.get().ReplaceAllLiteral(src, repl)
}
func (l *lazyRegexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte {
	return l.get().ReplaceAllFunc(src, repl)
}
func (l *lazyRegexp) ReplaceAllString(src, repl string) string {
	return l.get().ReplaceAllString(src, repl)
}
func (l *lazyRegexp) ReplaceAllLiteralString(src, repl string) string {
	return l.get().ReplaceAllLiteralString(src, repl)
}
func (l *lazyRegexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	return l.get().ReplaceAllStringFunc(src, repl)
}
func (l *lazyRegexp) Split(s string, n int) []string { return l.get().Split(s, n) }
func (l *lazyRegexp) SubexpNames() []string          { return l.get().SubexpNames() }
func (l *lazyRegexp) SubexpIndex(name string) int    { return l.get().SubexpIndex(name) }
func (l *lazyRegexp) NumSubexp() int                 { return l.get().NumSubexp() }
func (l *lazyRegexp) String() string                 { return l.pat }
