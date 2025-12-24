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

// Package config provides extensible configuration for Gazelle libraries.
//
// Packages may define Configurers which add support for new command-line
// options and directive comments in build files. Note that the
// language.Language interface embeds Configurer, so each language extension
// has the opportunity
//
// When Gazelle walks the directory trees in a repository, it calls the
// Configure method of each Configurer to produce a Config object.
// Config objects are passed as arguments to most functions in Gazelle, so
// this mechanism may be used to control many aspects of Gazelle's behavior.
package config

import (
	"context"

	"github.com/bazel-contrib/bazel-gazelle/v2/rule"
)

// Config holds information about how Gazelle should run. This is based on
// command line arguments, directives, other hints in build files.
//
// A Config applies to a single directory. A Config is created for the
// repository root directory, then copied and modified for each subdirectory.
//
// Config itself contains only general information. Most configuration
// information is language-specific and is stored in Exts. This information
// is modified by extensions that implement Configurer.
type Config struct {
	// WorkDir is the effective working directory, used to resolve relative
	// paths on the command line. When Gazelle is invoked with 'bazel run',
	// this is set by BUILD_WORKSPACE_DIRECTORY.
	WorkDir string

	// RepoRoot is the absolute, canonical path to the root directory of the
	// repository with all symlinks resolved.
	RepoRoot string

	// RepoName is the name of the repository.
	RepoName string

	// ReadBuildFilesDir is the absolute path to a directory where
	// build files should be read from instead of RepoRoot.
	ReadBuildFilesDir string

	// WriteBuildFilesDir is the absolute path to a directory where
	// build files should be written to instead of RepoRoot.
	WriteBuildFilesDir string

	// ValidBuildFileNames is a list of base names that are considered valid
	// build files. Some repositories may have files named "BUILD" that are not
	// used by Bazel and should be ignored. Must contain at least one string.
	ValidBuildFileNames []string

	// ShouldFix determines whether Gazelle attempts to remove and replace
	// usage of deprecated rules.
	ShouldFix bool

	// Strict determines how Gazelle handles build file and directive errors. When
	// set, Gazelle will exit with non-zero value after logging such errors.
	Strict bool

	// IndexLibraries determines whether Gazelle should build an index of
	// libraries in the workspace for dependency resolution
	IndexLibraries bool

	// When IndexLazy is true, Gazelle builds its index lazily, only reading
	// specific directories indicated by the user or by extensions.
	// When false, Gazelle indexes all directories.
	IndexLazy bool

	// KindMap maps from a kind name to its replacement. It provides a way for
	// users to customize the kind of rules created by Gazelle, via
	// # gazelle:map_kind.
	KindMap map[string]MappedKind

	// AliasMap maps a wrapper macro name to the kind of rule that it wraps.
	// It provides a way for users to define custom macros that generate rules
	// that are understood by gazelle, while still allowing gazelle to update
	// the attrs for the macro calls. Configured via # gazelle:macro.
	AliasMap map[string]string

	// Repos is a list of repository rules declared in the main WORKSPACE file
	// or in macros called by the main WORKSPACE file. This may affect rule
	// generation and dependency resolution.
	Repos []*rule.Rule

	// Langs is a list of language names which Gazelle should process.
	// An empty list means "all languages".
	Langs []string

	// Exts is a set of configurable extensions. Generally, each language
	// has its own set of extensions, but other modules may provide their own
	// extensions as well. Values in here may be populated by command line
	// arguments, directives in build files, or other mechanisms.
	Exts map[string]interface{}

	// Whether Gazelle is loaded as a Bzlmod 'bazel_dep'.
	Bzlmod bool

	// ModuleToApparentName is a function that maps the name of a Bazel module
	// to the apparent name (repo_name) specified in the MODULE.bazel file. It
	// returns the empty string if the module is not found.
	ModuleToApparentName func(string) string
}

// MappedKind describes a replacement to use for a built-in kind.
type MappedKind struct {
	FromKind, KindName, KindLoad string
}

func New() *Config {
	return &Config{
		ValidBuildFileNames: DefaultValidBuildFileNames,
		Exts:                make(map[string]any),
	}
}

// Clone creates a copy of the configuration for use in a subdirectory.
// Note that the Exts map is copied, but its contents are not.
// Configurer.Configure should do this, if needed.
func (c *Config) Clone() *Config {
	cc := *c
	cc.Exts = make(map[string]interface{})
	for k, v := range c.Exts {
		cc.Exts[k] = v
	}
	cc.KindMap = make(map[string]MappedKind)
	for k, v := range c.KindMap {
		cc.KindMap[k] = v
	}
	return &cc
}

var DefaultValidBuildFileNames = []string{"BUILD.bazel", "BUILD"}

// IsValidBuildFileName returns true if a file with the given base name
// should be treated as a build file.
func (c *Config) IsValidBuildFileName(name string) bool {
	for _, n := range c.ValidBuildFileNames {
		if name == n {
			return true
		}
	}
	return false
}

// DefaultBuildFileName returns the base name used to create new build files.
func (c *Config) DefaultBuildFileName() string {
	return c.ValidBuildFileNames[0]
}

// Configurer may be implemented by an extension to support language-specific
// configuration.
type Configurer interface {
	// KnownDirectives returns a list of directive names this Configurer can
	// interpret. Gazelle reports errors for directives that are not recognized
	// by any Configurer.
	KnownDirectives() []string

	// Configure modifies the configuration using directives and other information
	// extracted from a build file. Configure is called in each directory Gazelle
	// visits and all parent directories, whether or not Gazelle will update the
	// build file in the visited directory. Configure is called in parent
	// directories first, but otherwise, the order is not defined.
	Configure(context.Context, ConfigureArgs) error
}

type ConfigureArgs struct {
	// Config is the configuration for the current directory.
	Config *Config

	// Rel is the slash-separated path to the directory, relative to the
	// repository root ("" for the root directory itself).
	Rel string

	// File is the build file for the directory. File is nil if there is
	// no existing build file.
	File *rule.File
}
