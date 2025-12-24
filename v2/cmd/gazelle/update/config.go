/* Copyright 2025 The Bazel Authors. All rights reserved.

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

package update

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bazel-contrib/bazel-gazelle/v2/compat"
	"github.com/bazel-contrib/bazel-gazelle/v2/config"
	"github.com/bazel-contrib/bazel-gazelle/v2/internal/wspace"
	"github.com/bazelbuild/bazel-gazelle/internal/module"
)

// CommonConfigurer handles language-agnostic command-line flags and directives,
// i.e., those that apply to Config itself and not to Config.Exts.
type CommonConfigurer struct {
	repoRoot                          string
	indexLibraries, indexLazy, strict bool
	langCsv                           string
	bzlmod                            bool
}

var _ config.Configurer = (*CommonConfigurer)(nil)
var _ compat.FlagConfigurer = (*CommonConfigurer)(nil)

func (cc *CommonConfigurer) RegisterFlags(fs *flag.FlagSet, cmd string, c *config.Config) {
	cc.indexLibraries = true
	cc.indexLazy = false
	fs.StringVar(&cc.repoRoot, "repo_root", "", "path to a directory which corresponds to go_prefix, otherwise gazelle searches for it.")
	fs.Var(indexFlag{indexLibraries: &cc.indexLibraries, indexLazy: &cc.indexLazy}, "index", "determines how Gazelle indexes library rules. 'all' means index all libraries in all repo directories. 'lazy' means specific directories, determined by extensions. 'none' means indexing is disabled.")
	fs.BoolVar(&cc.strict, "strict", false, "when true, gazelle will exit with none-zero value for build file syntax errors or unknown directives")
	fs.StringVar(&cc.langCsv, "lang", "", "if non-empty, process only these languages (e.g. \"go,proto\")")
	fs.BoolVar(&cc.bzlmod, "bzlmod", false, "for internal usage only")
}

func (cc *CommonConfigurer) CheckFlags(fs *flag.FlagSet, c *config.Config) error {
	var err error
	if cc.repoRoot == "" {
		if wsDir := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); wsDir != "" {
			cc.repoRoot = wsDir
		} else if parent, err := wspace.FindRepoRoot(c.WorkDir); err == nil {
			cc.repoRoot = parent
		} else {
			return fmt.Errorf("-repo_root not specified, and WORKSPACE cannot be found: %v", err)
		}
	}
	if filepath.IsAbs(cc.repoRoot) {
		c.RepoRoot = cc.repoRoot
	} else {
		c.RepoRoot = filepath.Join(c.WorkDir, cc.repoRoot)
	}
	c.RepoRoot, err = filepath.EvalSymlinks(c.RepoRoot)
	if err != nil {
		return fmt.Errorf("%s: failed to resolve symlinks: %v", cc.repoRoot, err)
	}
	c.RepoName, err = extractRepositoryName(c.RepoRoot)
	if err != nil {
		return fmt.Errorf("failed to extract repository name: %v", err)
	}
	c.IndexLibraries = cc.indexLibraries
	c.IndexLazy = cc.indexLazy
	c.Strict = cc.strict
	if len(cc.langCsv) > 0 {
		c.Langs = strings.Split(cc.langCsv, ",")
	}
	c.Bzlmod = cc.bzlmod
	c.ModuleToApparentName, err = module.ExtractModuleToApparentNameMapping(c.RepoRoot)
	if err != nil {
		return fmt.Errorf("failed to parse MODULE.bazel: %v", err)
	}
	return nil
}

func (cc *CommonConfigurer) KnownDirectives() []string {
	return []string{"map_kind", "alias_kind", "lang"}
}
