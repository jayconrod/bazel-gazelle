module github.com/bazel-contrib/bazel-gazelle/v2

go 1.24.11

require (
	github.com/bazelbuild/buildtools v0.0.0-20250930140053-2eb4fccefb52
	github.com/bazelbuild/rules_go v0.53.0
	github.com/bmatcuk/doublestar/v4 v4.9.1
	github.com/fsnotify/fsnotify v1.7.0
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.6.0
	github.com/pmezard/go-difflib v1.0.0
	golang.org/x/mod v0.20.0
	golang.org/x/sync v0.10.0
	golang.org/x/tools/go/vcs v0.1.0-deprecated
	google.golang.org/protobuf v1.36.3
	github.com/bazelbuild/bazel-gazelle v1.0.0-1
)

require golang.org/x/sys v0.28.0 // indirect

replace github.com/bazelbuild/bazel-gazelle => ..
