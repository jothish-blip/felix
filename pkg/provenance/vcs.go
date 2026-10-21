package provenance

import (
	"context"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"
)

// ResolveVCSInfo discovers source-control revision and dirty status across compile-time build info,
// local Git repository state, and continuous integration environment variables.
//
// Rules enforced:
// 1. Distinguishes build-time revision from runtime checkout revision when both are present.
// 2. Correctly flags dirty worktrees when uncommitted changes exist.
// 3. Fails closed and records "unavailable" without crashing if git is absent or dir is not a repo.
// 4. Never fabricates synthetic SHAs or build values.
func ResolveVCSInfo(ctx context.Context, dir string) VCSInfo {
	var info VCSInfo

	// 1. Inspect compile-time build info embedded by the Go toolchain
	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		for _, setting := range bi.Settings {
			switch setting.Key {
			case "vcs.revision":
				if strings.TrimSpace(setting.Value) != "" {
					info.BuildRevision = strings.TrimSpace(setting.Value)
				}
			case "vcs.time":
				if strings.TrimSpace(setting.Value) != "" {
					info.BuildTime = strings.TrimSpace(setting.Value)
				}
			case "vcs.modified":
				dirty := setting.Value == "true"
				info.BuildDirty = &dirty
			}
		}
	}

	// 2. Query runtime Git worktree if directory is provided or accessible
	runtimeRev, runtimeDirty := queryGitWorktree(ctx, dir)
	if runtimeRev != "" {
		info.RuntimeRevision = runtimeRev
		info.RuntimeDirty = runtimeDirty
	} else {
		// 3. Fallback to CI environment variables (e.g. GitHub Actions, GitLab CI)
		if envSHA := strings.TrimSpace(os.Getenv("GITHUB_SHA")); envSHA != "" {
			info.RuntimeRevision = envSHA
		} else if envSHA := strings.TrimSpace(os.Getenv("GIT_COMMIT")); envSHA != "" {
			info.RuntimeRevision = envSHA
		}
	}

	// 4. Determine authoritative VCSSource
	hasBuild := info.BuildRevision != ""
	hasRuntime := info.RuntimeRevision != ""
	if hasBuild && hasRuntime {
		info.VCSSource = "build_info+git_worktree"
	} else if hasBuild {
		info.VCSSource = "build_info"
	} else if hasRuntime {
		if info.RuntimeDirty != nil {
			info.VCSSource = "git_worktree"
		} else {
			info.VCSSource = "environment"
		}
	} else {
		info.VCSSource = "unavailable"
	}

	return info
}

// queryGitWorktree runs safe, timeout-bounded git commands to detect commit SHA and dirty state.
func queryGitWorktree(parentCtx context.Context, dir string) (string, *bool) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return "", nil
	}

	rev := strings.TrimSpace(string(out))
	if rev == "" || len(rev) < 7 {
		return "", nil
	}

	// Check worktree dirty status via porcelain status
	statusCmd := exec.CommandContext(ctx, "git", "status", "--porcelain")
	if dir != "" {
		statusCmd.Dir = dir
	}
	statusOut, err := statusCmd.Output()
	if err != nil {
		return rev, nil
	}

	isDirty := len(strings.TrimSpace(string(statusOut))) > 0
	return rev, &isDirty
}
