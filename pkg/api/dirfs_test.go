package api

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/testutil"
)

func TestAbsDirPath(t *testing.T) {

	// Tree:
	// namespace/repo/
	// 	- repo
	// 		- dir/
	//			- subdir/

	repoDir := &Dir{
		DirID: uuid.New(),
		Name:  "repo",
	}

	dir := &Dir{
		DirID:    uuid.New(),
		Name:     "dir",
		ParentID: repoDir.DirID,
	}

	subdir := &Dir{
		DirID:    uuid.New(),
		Name:     "subdir",
		ParentID: dir.DirID,
	}

	repoPath := DirPath("namespace/repo")
	dirPath := DirPath("namespace/repo/dir")
	subdirPath := DirPath("namespace/repo/dir/subdir")

	cases := map[string]struct {
		dirID    *uuid.UUID
		tree     Tree
		expected *DirPath
		err      error
	}{
		"path of repo with tree rooted at repo": {
			dirID: repoDir.DirID,
			tree: Tree{
				ParentPath: "namespace",
				RootDir:    repoDir,
				Dirs: map[uuid.UUID]*Dir{
					*repoDir.DirID: repoDir,
				},
				Secrets: map[uuid.UUID]*Secret{},
			},
			expected: &repoPath,
			err:      nil,
		},
		"path of dir with tree rooted at repo": {
			dirID: dir.DirID,
			tree: Tree{
				ParentPath: "namespace",
				RootDir:    repoDir,
				Dirs: map[uuid.UUID]*Dir{
					*dir.DirID: dir,
				},
				Secrets: map[uuid.UUID]*Secret{},
			},
			expected: &dirPath,
			err:      nil,
		},
		"path of dir with tree rooted at dir": {
			dirID: dir.DirID,
			tree: Tree{
				ParentPath: "namespace/repo",
				RootDir:    dir,
				Dirs: map[uuid.UUID]*Dir{
					*dir.DirID:    dir,
					*subdir.DirID: subdir,
				},
				Secrets: map[uuid.UUID]*Secret{},
			},
			expected: &dirPath,
			err:      nil,
		},
		"path of subdir with tree rooted at dir": {
			dirID: subdir.DirID,
			tree: Tree{
				ParentPath: "namespace/repo",
				RootDir:    dir,
				Dirs: map[uuid.UUID]*Dir{
					*dir.DirID:    dir,
					*subdir.DirID: subdir,
				},
				Secrets: map[uuid.UUID]*Secret{},
			},
			expected: &subdirPath,
			err:      nil,
		},
		"path of dir with dir not in tree": {
			dirID: dir.DirID,
			tree: Tree{
				ParentPath: "namespace",
				RootDir:    repoDir,
				Dirs:       map[uuid.UUID]*Dir{},
				Secrets:    map[uuid.UUID]*Secret{},
			},
			expected: nil,
			err:      ErrDirNotFound,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual, err := tc.tree.AbsDirPath(tc.dirID)

			// Assert
			testutil.Compare(t, err, tc.err)
			testutil.Compare(t, actual, tc.expected)
		})
	}
}
