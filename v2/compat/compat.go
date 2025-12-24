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

// Package compat provides interfaces and adapters, supporting compatibility
// between Gazelle v1 and v2.
package compat

import (
	"context"
	"flag"

	"github.com/bazel-contrib/bazel-gazelle/v2/config"
	configv1 "github.com/bazelbuild/bazel-gazelle/config"
)

// FlagConfigurer allows an extension to define and validate command-line flags.
//
// The v2 Configurer interface does not have these methods. These methods are
// identical to the corresponding methods in the v1 interface, so a v1
// Configurer implementation satisfies this.

// This functionality is not supported in v2 and was removed from the
// config.Configurer interface.
//
//	Implementations of this interface are used by
//
// v1 but are ignored by v2.
type FlagConfigurer interface {
	// RegisterFlags registers command-line flags used by the extension. This
	// method is called once with the root configuration when Gazelle
	// starts. RegisterFlags may set an initial values in Config.Exts. When flags
	// are set, they should modify these values.
	RegisterFlags(fs *flag.FlagSet, cmd string, c *config.Config)

	// CheckFlags validates the configuration after command line flags are parsed.
	// This is called once with the root configuration when Gazelle starts.
	// CheckFlags may set default values in flags or make implied changes.
	CheckFlags(fs *flag.FlagSet, c *config.Config) error
}

var _ FlagConfigurer = (configv1.Configurer)(nil)

// ConfigurerV2 returns v and true if v satisfies the v2 Configurer interface,
// or and adapter and true if v satisifes the v1 Configurer interface.
// ConfigurerV2 returns nil and false if v does not satisfy either interface.
func ConfigurerV2(v any) (config.Configurer, bool) {
	switch v := v.(type) {
	case config.Configurer:
		return v, true
	case configv1.Configurer:
		return configurerAdapter{v1: v}, true
	default:
		return nil, false
	}
}

type configurerAdapter struct {
	v1 configv1.Configurer
}

var _ config.Configurer = configurerAdapter{}

func (c configurerAdapter) KnownDirectives() []string {
	return c.v1.KnownDirectives()
}

func (c configurerAdapter) Configure(ctx context.Context, args config.ConfigureArgs) error {
	c.v1.Configure(args.Config, args.Rel, args.File)
	return nil
}
