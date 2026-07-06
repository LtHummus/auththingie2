package rules

import "unicode/utf8"

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// internalMatch matches input against patterns such as `/api/*`
// a * in a pattern matches many characters. A ? matches a single character. We can not use path.Match here because
// we want * to match across separators (e.g. `/api/*` would match `/api/foo` but not `/api/v1/foo). Note for future self
// using the library `doublestar` could work here, but would break configs since `*` won't match across separators, but
// ** will
//
// note that there are two versions of this function, one that is optimized for pure-ASCII strings and one that can
// handle the wider characters of unicode. We do a simple check to see if both the candidate and pattern are pure ascii
// and if so, we do the faster ASCII version, otherwise fall back to the unicode version. Based on benchmarking, the
// ASCII version is about 1.7-2.4x as fast as the unicode one
func internalMatch(pattern string, candidate string) bool {
	if isASCII(pattern) && isASCII(candidate) {
		return internalMatchASCII(pattern, candidate)
	}

	return internalMatchUnicode(pattern, candidate)
}

func internalMatchASCII(pattern string, candidate string) bool {
	p := 0
	c := 0

	lastStar := -1
	starMatches := 0

	for c < len(candidate) {
		if p < len(pattern) && pattern[p] == '*' {
			lastStar = p
			starMatches = c
			p++
		} else if p < len(pattern) && (pattern[p] == '?' || pattern[p] == candidate[c]) {
			p++
			c++
		} else if lastStar != -1 {
			starMatches++
			p = lastStar + 1
			c = starMatches
		} else {
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}

func internalMatchUnicode(pattern string, candidate string) bool {
	patternRunes := []rune(pattern)
	candidateRunes := []rune(candidate)

	p := 0
	c := 0

	lastStar := -1
	starMatches := 0

	for c < len(candidateRunes) {
		if p < len(patternRunes) && patternRunes[p] == '*' {
			lastStar = p
			starMatches = c
			p++
		} else if p < len(patternRunes) && (patternRunes[p] == '?' || patternRunes[p] == candidateRunes[c]) {
			p++
			c++
		} else if lastStar != -1 {
			starMatches++
			p = lastStar + 1
			c = starMatches
		} else {
			return false
		}
	}

	for p < len(patternRunes) && patternRunes[p] == '*' {
		p++
	}

	return p == len(patternRunes)
}
