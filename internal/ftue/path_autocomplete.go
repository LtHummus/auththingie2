package ftue

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
)

func PathAutoComplete(curr string) []string {
	currLocation := path.Dir(curr)
	var children []string
	err := filepath.WalkDir(currLocation, func(p string, d fs.DirEntry, err error) error {
		if d.Name() == path.Base(curr) {
			return nil
		}
		if d.IsDir() {
			children = append(children, fmt.Sprintf("%s/", p))
			return filepath.SkipDir
		} else {
			return nil
		}
	})
	if err != nil {
		panic(err)
	}

	return children
}
