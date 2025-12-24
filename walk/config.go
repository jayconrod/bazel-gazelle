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

package walk

import (
	"context"
	"flag"
	"log"

	"github.com/bazel-contrib/bazel-gazelle/v2/config"
	"github.com/bazel-contrib/bazel-gazelle/v2/rule"
	v2 "github.com/bazel-contrib/bazel-gazelle/v2/walk"
)

// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/walk.Configurer instead.
type Configurer struct {
	v2 v2.Configurer
}

func (cc *Configurer) RegisterFlags(fs *flag.FlagSet, cmd string, c *config.Config) {
	cc.v2.RegisterFlags(fs, cmd, c)
}

func (cc *Configurer) CheckFlags(fs *flag.FlagSet, c *config.Config) error {
	return cc.v2.CheckFlags(fs, c)
}

func (cc *Configurer) KnownDirectives() []string {
	return cc.v2.KnownDirectives()
}

func (cc *Configurer) Configure(c *config.Config, rel string, f *rule.File) {
	err := cc.v2.Configure(context.Background(), config.ConfigureArgs{
		Config: c,
		Rel:    rel,
		File:   f,
	})
	if err != nil {
		log.Print(err)
	}
}
