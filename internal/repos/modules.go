/* Copyright 2018 The Bazel Authors. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package repos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bazelbuild/bazel-gazelle/internal/label"
)

type module struct {
	Path, Version string
	Main          bool
}

func importRepoRulesModules(filename string) (repos []Repo, err error) {
	dir := filepath.Dir(filename)
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		if werr := cmd.Wait(); err == nil && werr != nil {
			err = werr
		}
	}()
	dec := json.NewDecoder(buf)
	for dec.More() {
		var mod module
		if err := dec.Decode(&mod); err != nil {
			return nil, err
		}
		var tag, commit string
		if strings.HasPrefix(mod.Version, "v0.0.0-") {
			if i := strings.LastIndex(mod.Version, "-"); i < 0 {
				return nil, fmt.Errorf("failed to parse version for %s: %q", mod.Path, mod.Version)
			} else {
				commit = mod.Version[i+1:]
			}
		} else {
			tag = mod.Version
		}
		repos = append(repos, Repo{
			Name:     label.ImportPathToBazelRepoName(mod.Path),
			GoPrefix: mod.Path,
			Commit:   commit,
			Tag:      tag,
		})
	}
	return repos, nil
}
