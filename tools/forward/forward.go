package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/bazel-contrib/bazel-gazelle/v2/rule"
)

func main() {
	wd := os.Getenv("BUILD_WORKING_DIRECTORY")
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	if err := run(wd, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(wd string, args []string) error {
	flags := flag.NewFlagSet("forward", flag.ContinueOnError)
	var shim bool
	flags.BoolVar(&shim, "shim", false, "whether to replace the original package with shims")
	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: forward directories...\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return fmt.Errorf("no directories given")
	}
	srcDirs := flags.Args()

	modRootDir, err := findModRoot(wd)
	if err != nil {
		return err
	}

	for _, dir := range srcDirs {
		srcDir := filepath.Join(wd, dir)
		srcRel, err := filepath.Rel(modRootDir, srcDir)
		if err != nil {
			return err
		}
		srcRel = filepath.ToSlash(srcRel)
		srcPkg := path.Join("github.com/bazelbuild/bazel-gazelle", srcRel)

		dstDir := filepath.Join(modRootDir, "v2", srcRel)
		dstPkg := path.Join("github.com/bazel-contrib/bazel-gazelle/v2", srcRel)

		if err := copyDir(srcDir, dstDir); err != nil {
			return err
		}

		if err := updateDstBuildFile(dstDir, dstPkg); err != nil {
			return err
		}

		if shim {
			if err := shimPackage(srcDir, dstPkg); err != nil {
				return err
			}
			if err := rewriteAllImports(modRootDir, srcPkg, dstPkg); err != nil {
				return err
			}
		}
	}

	// Run gazelle to fix dependencies
	cmd := exec.Command("gazelle", "-bzlmod", "-external=static")
	cmd.Dir = modRootDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running gazelle: %w", err)
	}

	// Update the source list to fix go_repository_tools.
	cmd = exec.Command("go", "run", "internal/list_repository_tools_srcs.go", "-dir", modRootDir, "-generate", "internal/go_repository_tools_srcs.bzl")
	cmd.Dir = modRootDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("updating go_repository_tools_srcs.bzl: %w", err)
	}

	return nil
}

func rewriteAllImports(root, srcPkg, dstPkg string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		return rewriteImportsInFile(path, srcPkg, dstPkg)
	})
}

func rewriteImportsInFile(path, shimPkg, destPkg string) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	changed := false
	for _, imp := range f.Imports {
		// imp.Path.Value is quoted, e.g. "\"example.com/old\""
		val := strings.Trim(imp.Path.Value, "\"")
		if val == shimPkg {
			imp.Path.Value = fmt.Sprintf("\"%s\"", destPkg)
			changed = true
		}
	}

	if changed {
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, f); err != nil {
			return err
		}
		formatted, err := format.Source(buf.Bytes())
		if err != nil {
			return fmt.Errorf("formatting rewritten file %s: %w", path, err)
		}
		if err := os.WriteFile(path, formatted, 0666); err != nil {
			return err
		}
	}
	return nil
}

func findModRoot(dir string) (string, error) {
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if dir == parent {
			return "", fmt.Errorf("could not locate go.mod in any parent directory")
		}
		dir = parent
	}
}

func copyDir(src, dst string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("copying %s to %s: %w", src, dst, err)
		}
	}()

	// If dst doesn't exist, create it
	if err := os.MkdirAll(dst, 0777); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursive copy
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if strings.HasSuffix(entry.Name(), ".go") {
				if err := copyGoFile(srcPath, dstPath); err != nil {
					return err
				}
			} else {
				if err := copyFile(srcPath, dstPath); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func copyGoFile(src, dst string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("copying go file %s to %s: %w", src, dst, err)
		}
	}()

	// Read source
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	// Rewrite imports
	// Replace "github.com/bazelbuild/bazel-gazelle/internal/..."
	// with "github.com/bazel-contrib/bazel-gazelle/v2/internal/..."
	oldPrefix := "github.com/bazelbuild/bazel-gazelle/internal/"
	newPrefix := "github.com/bazel-contrib/bazel-gazelle/v2/internal/"

	for _, imp := range f.Imports {
		if imp.Path == nil {
			continue
		}
		pkg := strings.Trim(imp.Path.Value, "\"")
		if withoutPrefix, ok := strings.CutPrefix(pkg, oldPrefix); ok {
			imp.Path.Value = fmt.Sprintf(`"%s%s"`, newPrefix, withoutPrefix)
		}
	}

	// Format and write
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return err
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("formatting: %w", err)
	}

	return os.WriteFile(dst, formatted, 0666)
}

func copyFile(src, dst string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("copying %s to %s: %w", dst, dst, err)
		}
	}()

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(out, in)
	return err
}

func updateDstBuildFile(dir, dstPkg string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("updating BUILD file in %s: %w", dir, err)
		}
	}()

	buildPath := filepath.Join(dir, "BUILD.bazel")
	if _, err := os.Stat(buildPath); os.IsNotExist(err) {
		buildPath = filepath.Join(dir, "BUILD")
		if _, err := os.Stat(buildPath); os.IsNotExist(err) {
			return nil
		}
	}

	f, err := rule.LoadFile(buildPath, "")
	if err != nil {
		return err
	}

	// Identify aliases to delete (specifically name="go_default_library")
	for _, r := range f.Rules {
		if r.Kind() == "alias" && r.Name() == "go_default_library" {
			r.Delete()
		}
		if kind := r.Kind(); kind == "go_library" || kind == "go_binary" || kind == "go_test" {
			if r.Attr("importpath") != nil {
				r.SetAttr("importpath", dstPkg)
			}
		}
	}

	return f.Save(buildPath)
}

func shimPackage(dir, shimPkg string) error {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse directory: %v", err)
	}

	// Delete all test files
	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read dir: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_test.go") {
			path := filepath.Join(dir, f.Name())
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove test file %s: %v", path, err)
			}
			fmt.Printf("Removed %s\n", path)
		}
	}

	for _, pkg := range pkgs {
		for filename, file := range pkg.Files {
			if err := shimFile(file, fset, filename, shimPkg); err != nil {
				return fmt.Errorf("failed to process %s: %v", filename, err)
			}
		}
	}

	return nil
}

func shimFile(f *ast.File, fset *token.FileSet, filename, targetPkg string) error {
	var buf bytes.Buffer

	// Preserve build constraints and copyright headers (comments before package decl)
	// using AST positions to preserve vertical spacing.
	lastLine := 1
	for _, group := range f.Comments {
		if group.Pos() >= f.Package {
			break
		}

		// Calculate newlines before this group
		groupLine := fset.Position(group.Pos()).Line
		newlines := groupLine - lastLine
		for i := 0; i < newlines; i++ {
			buf.WriteString("\n")
		}

		// Print the comment group
		for _, comment := range group.List {
			buf.WriteString(comment.Text + "\n")
		}

		lastLine = fset.Position(group.End()).Line + 1
	}

	// Calculate newlines before package declaration
	pkgLine := fset.Position(f.Package).Line
	newlines := pkgLine - lastLine
	for i := 0; i < newlines; i++ {
		buf.WriteString("\n")
	}

	pkgName := f.Name.Name
	if pkgName == "main" {
		log.Printf("Skipping main package file: %s", filename)
		return nil
	}

	buf.WriteString(fmt.Sprintf("package %s\n\n", pkgName))

	// Import the target package with a specific alias to avoid collisions
	targetName := "v2"
	buf.WriteString(fmt.Sprintf("import %s \"%s\"\n", targetName, targetPkg))

	// Preserve original imports to ensure types used in signatures can be resolved.
	// goimports will remove any that end up being unused.
	for _, imp := range f.Imports {
		if imp.Name != nil {
			buf.WriteString(fmt.Sprintf("import %s %s\n", imp.Name.Name, imp.Path.Value))
		} else {
			buf.WriteString(fmt.Sprintf("import %s\n", imp.Path.Value))
		}
	}
	buf.WriteString("\n")

	// Iterate definitions and generate shims
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}

			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						writeDoc(&buf, d.Doc, targetPkg, s.Name.Name)
						// type T = dest.T
						buf.WriteString(fmt.Sprintf("type %s = %s.%s\n\n", s.Name.Name, targetName, s.Name.Name))
					}
				case *ast.ValueSpec:
					for _, name := range s.Names {
						if name.IsExported() {
							writeDoc(&buf, d.Doc, targetPkg, name.Name)
							kind := "var"
							if d.Tok == token.CONST {
								kind = "const"
							}
							// var V = dest.V or const C = dest.C
							buf.WriteString(fmt.Sprintf("%s %s = %s.%s\n\n", kind, name.Name, targetName, name.Name))
						}
					}
				}
			}

		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.IsExported() {
				writeDoc(&buf, d.Doc, targetPkg, d.Name.Name)

				// Signature
				var typeBuf bytes.Buffer
				if err := printer.Fprint(&typeBuf, fset, d.Type); err != nil {
					return err
				}
				sig := typeBuf.String()
				sig = strings.TrimPrefix(sig, "func")

				// Call arguments
				args := formatCallArgs(d.Type.Params)

				buf.WriteString(fmt.Sprintf("func %s%s {\n", d.Name.Name, sig))

				// Return?
				if d.Type.Results != nil && len(d.Type.Results.List) > 0 {
					buf.WriteString(fmt.Sprintf("\treturn %s.%s(%s)\n", targetName, d.Name.Name, args))
				} else {
					buf.WriteString(fmt.Sprintf("\t%s.%s(%s)\n", targetName, d.Name.Name, args))
				}
				buf.WriteString("}\n\n")
			}
		}
	}

	// Write back
	if err := os.WriteFile(filename, buf.Bytes(), 0666); err != nil {
		return err
	}

	// Run goimports to remove unused imports and format
	cmd := exec.Command("goimports", "-w", filename)
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func writeDoc(buf *bytes.Buffer, doc *ast.CommentGroup, targetPkg, name string) {
	if doc != nil {
		for _, c := range doc.List {
			buf.WriteString(c.Text + "\n")
		}
		if len(doc.List) > 0 {
			buf.WriteString("//\n")
		}
	}
	fmt.Fprintf(buf, "// Deprecated: Use %s.%s instead.\n", targetPkg, name)
}

func formatCallArgs(params *ast.FieldList) string {
	if params == nil {
		return ""
	}
	var args []string
	for _, field := range params.List {
		for _, name := range field.Names {
			args = append(args, name.Name)
		}
	}

	// Handle variadic ...
	if len(args) > 0 {
		// Check last field type for ellipsis
		lastField := params.List[len(params.List)-1]
		if _, ok := lastField.Type.(*ast.Ellipsis); ok {
			args[len(args)-1] += "..."
		}
	}

	return strings.Join(args, ", ")
}
