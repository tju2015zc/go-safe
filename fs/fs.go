package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SecureFS struct {
	safeBaseDir    string
	whitelistRegex *regexp.Regexp
	allowRelative  bool
	strictMode     bool
}

var s *SecureFS

func initSecureFS(baseDir string) error {
	absDir, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("securefs初始化失败: %v", err)
	}
	s = &SecureFS{
		safeBaseDir:   absDir,
		allowRelative: false,
		strictMode:    false,
	}
	var pattern string
	switch {
	case s.strictMode:
		pattern = "^([\\w-]+/)*([\\w.]+)?$"
	case s.allowRelative:
		pattern = "^(?:\\.+/)?([\\w-/]+)$"
	default:
		pattern = "^([\\w-/]+)$"
	}
	s.whitelistRegex = regexp.MustCompile(pattern)
	return nil
}

func sanitize(rawPath string) (string, error) {
	if rawPath == "" {
		return "", errors.New("路径不能为空")
	}
	if s == nil {
		err := initSecureFS("/")
		if err != nil {
			return "", err
		}
	}
	switch {
	case filepath.IsAbs(rawPath):
		return "", errors.New("禁止绝对路径")
	case s.allowRelative && strings.Contains(rawPath, ".."):
		return "", errors.New("检测到相对路径")
	}
	fullPath := filepath.Join(s.safeBaseDir, rawPath)
	cleanPath := filepath.Clean(fullPath)
	if !isInBaseDir(cleanPath, s.safeBaseDir) {
		return "", errors.New("路径越界访问")
	}
	return cleanPath, nil
}

func isInBaseDir(target, base string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return !strings.Contains(rel, "..")
}

func ReadDir(name string) ([]fs.DirEntry, error) {
	cleanPath, err := sanitize(name)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(cleanPath)
}

func checkDirPermissions(path string, required os.FileMode) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return (info.Mode().Perm() & required) == required
}

func SetWhiteListPattern(pattern string) error {
	if len(pattern) == 0 {
		return fmt.Errorf("pattern不能为空")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	s.whitelistRegex = compiled
	return nil
}
