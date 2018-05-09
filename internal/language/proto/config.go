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

package proto

import (
	"flag"
	"fmt"
	"log"

	"github.com/bazelbuild/bazel-gazelle/internal/config"
	"github.com/bazelbuild/bazel-gazelle/internal/rule"
)

// ProtoConfig contains configuration values related to protos.
//
// This type is public because other languages need to generate rules based
// on protos, so this configuration may be relevant to them.
//
// Note that the Go extension may actually modify these values
// (see golang.inferProtoMode).
type ProtoConfig struct {
	// Mode determines how rules are generated for protos.
	Mode Mode

	// ModeExplicit indicates whether the proto mode was set explicitly.
	ModeExplicit bool
}

func GetProtoConfig(c *config.Config) *ProtoConfig {
	return c.Exts[protoName].(*ProtoConfig)
}

// Mode determines how proto rules are generated.
type Mode int

const (
	// DefaultMode generates proto_library rules. Other languages should generate
	// library rules based on these (e.g., go_proto_library) and should ignore
	// checked-in generated files (e.g., .pb.go files) when there is a .proto
	// file with a similar name.
	DefaultMode Mode = iota

	// DisableMode ignores .proto files and generates empty proto_library rules.
	// Checked-in generated files (e.g., .pb.go files) should be treated as
	// normal sources.
	DisableMode

	// LegacyMode generates filegroups for .proto files if .pb.go files are
	// present in the same directory.
	LegacyMode
)

func ModeFromString(s string) (Mode, error) {
	switch s {
	case "default":
		return DefaultMode, nil
	case "disable":
		return DisableMode, nil
	case "legacy":
		return LegacyMode, nil
	default:
		return 0, fmt.Errorf("unrecognized proto mode: %q", s)
	}
}

func (m Mode) String() string {
	switch m {
	case DefaultMode:
		return "default"
	case DisableMode:
		return "disable"
	case LegacyMode:
		return "legacy"
	default:
		log.Panicf("unknown mode %d", m)
		return ""
	}
}

type modeFlag struct {
	mode     *Mode
	explicit *bool
}

func (f *modeFlag) Set(value string) error {
	if mode, err := ModeFromString(value); err != nil {
		return err
	} else {
		*f.mode = mode
		*f.explicit = true
		return nil
	}
}

func (f *modeFlag) String() string {
	var mode Mode
	if f != nil {
		mode = *f.mode
	}
	return mode.String()
}

func (_ *protoLang) RegisterFlags(fs *flag.FlagSet, cmd string, c *config.Config) {
	pc := &ProtoConfig{}
	c.Exts[protoName] = pc

	fs.Var(&modeFlag{&pc.Mode, &pc.ModeExplicit}, "proto", "default: generates new proto rules\n\tdisable: does not touch proto rules\n\t")
}

func (_ *protoLang) CheckFlags(fs *flag.FlagSet, c *config.Config) error {
	return nil
}

func (_ *protoLang) KnownDirectives() []string {
	return []string{"proto"}
}

func (_ *protoLang) Configure(c *config.Config, rel string, f *rule.File) {
	if f == nil {
		return
	}
	pc := &ProtoConfig{}
	*pc = *GetProtoConfig(c)
	c.Exts[protoName] = pc
	for _, d := range f.Directives {
		switch d.Key {
		case "proto":
			mode, err := ModeFromString(d.Value)
			if err != nil {
				log.Print(err)
				continue
			}
			pc.Mode = mode
			pc.ModeExplicit = true
		}
	}
}
