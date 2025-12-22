package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if wd := os.Getenv("BUILD_WORKING_DIRECTORY"); wd != "" {
		if err := os.Chdir(wd); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("forward", flag.ContinueOnError)
	var targetPkg string
	flags.StringVar(&targetPkg, "p", "", "location of package to generate shim for")
	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: forward -p <directory>\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if targetPkg == "" {
		return fmt.Errorf("target package -p not set")
	}
	dirs := flags.Args()
	if len(dirs) == 0 {
		return fmt.Errorf("no directories specified")
	}

	for _, dir := range dirs {
		if err := forwardPackage(targetPkg, dir); err != nil {
			return err
		}
	}
	return nil
}

func forwardPackage(targetPkg, dir string) error {
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
			if err := forwardFile(fset, filename, file, targetPkg); err != nil {
				return fmt.Errorf("failed to process %s: %v", filename, err)
			}
		}
	}

	return nil
}

func forwardFile(fset *token.FileSet, path string, f *ast.File, targetPkg string) error {
	var buf bytes.Buffer

	// Preserve build constraints (comments before package decl)
	for _, group := range f.Comments {
		if group.Pos() < f.Package {
			for _, comment := range group.List {
				// Simple heuristic for build tags or copyright headers
				// We keep everything before package decl just in case
				buf.WriteString(comment.Text + "\n")
			}
		}
	}

	pkgName := f.Name.Name
	if pkgName == "main" {
		log.Printf("Skipping main package file: %s", path)
		return nil
	}

	buf.WriteString(fmt.Sprintf("package %s\n\n", pkgName))

	// Import the target package with a specific alias to avoid collisions
	destAlias := "shim_pkg"
	buf.WriteString(fmt.Sprintf("import %s \"%s\"\n", destAlias, targetPkg))

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
						buf.WriteString(fmt.Sprintf("type %s = %s.%s\n\n", s.Name.Name, destAlias, s.Name.Name))
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
							buf.WriteString(fmt.Sprintf("%s %s = %s.%s\n\n", kind, name.Name, destAlias, name.Name))
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
					buf.WriteString(fmt.Sprintf("\treturn %s.%s(%s)\n", destAlias, d.Name.Name, args))
				} else {
					buf.WriteString(fmt.Sprintf("\t%s.%s(%s)\n", destAlias, d.Name.Name, args))
				}
				buf.WriteString("}\n\n")
			}
		}
	}

	// Write back
	if err := os.WriteFile(path, buf.Bytes(), 0666); err != nil {
		return err
	}

	// Run goimports
	cmd := exec.Command("goimports", "-w", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Just warn, don't fail, maybe goimports is not installed or syntax error (unlikely)
		log.Printf("Warning: goimports failed on %s: %v\nOutput: %s", path, err, out)
	}

	return nil
}

func writeDoc(buf *bytes.Buffer, doc *ast.CommentGroup, targetPkg, name string) {
	if doc != nil {
		for _, c := range doc.List {
			buf.WriteString(c.Text + "\n")
		}
	}
	buf.WriteString(fmt.Sprintf("//\n// Deprecated: Use %s.%s instead.\n", targetPkg, name))
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
