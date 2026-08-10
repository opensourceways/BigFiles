package server

import (
	"testing"

	"github.com/metalogical/BigFiles/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newSQLiteTestDB spins up an in-memory SQLite database, auto-migrates the
// lfs_obj table, and wires it as the global db.Db for the duration of a test.
// It returns a teardown func restoring the previous global handle.
//
// These tests need a real SQL engine because getLfsFiles/countLfsFiles build
// their WHERE clauses through gorm's chainable API; verifying the platform
// filter branch means asserting on actual query results rather than a mocked
// gorm stub (the previous Test_server_List only stubbed the functions and left
// the real SQL generation at 0% coverage).
func newSQLiteTestDB(t *testing.T) func() {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// :memory: databases are per-connection; pin a single connection so the
	// migrated schema and inserted rows stay visible across queries.
	sqlDB, err := gormDB.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	// Create the lfs_objs table with SQLite-compatible DDL. We cannot use
	// gorm.AutoMigrate(&db.LfsObj{}) because the LfsObj gorm tags carry
	// MySQL-specific clauses ("ON UPDATE CURRENT_TIMESTAMP") that SQLite
	// rejects. The columns below cover every field the query layer reads.
	require.NoError(t, gormDB.Exec(`CREATE TABLE lfs_objs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		oid TEXT,
		file_name TEXT,
		size INTEGER,
		platform TEXT,
		owner TEXT,
		repo TEXT,
		operator TEXT,
		exist INTEGER,
		update_time DATETIME,
		create_time DATETIME
	)`).Error)

	prev := db.Db
	db.Db = gormDB
	return func() {
		db.Db = prev
		_ = sqlDB.Close()
	}
}

// TestGetLfsFiles_PlatformFilter is a regression guard for the round-1 bugfix
// that made platform="" skip the platform filter (so the frontend "all" filter
// returns every file) while platform!="" narrows to that platform. Pinning both
// branches prevents a future refactor from silently re-breaking the "all" view.
func TestGetLfsFiles_PlatformFilter(t *testing.T) {
	teardown := newSQLiteTestDB(t)
	defer teardown()

	const owner, repo = "mindspore-ai", "repo"
	rows := []db.LfsObj{
		{Oid: "a", Owner: owner, Repo: repo, Platform: "github", Exist: 1, Size: 10},
		{Oid: "b", Owner: owner, Repo: repo, Platform: "gitee", Exist: 1, Size: 20},
		{Oid: "c", Owner: owner, Repo: repo, Platform: "github", Exist: 0, Size: 30}, // deleted, excluded
		{Oid: "d", Owner: "other-org", Repo: repo, Platform: "github", Exist: 1, Size: 40},
	}
	for i := range rows {
		require.NoError(t, db.Db.Create(&rows[i]).Error)
	}

	s := &server{}

	// platform == "" -> no platform WHERE clause: both exist=1 platforms returned
	all, err := s.getLfsFiles(owner, repo, "", 1, 10)
	require.NoError(t, err)
	oids := oidsOf(all)
	assert.ElementsMatch(t, []string{"a", "b"}, oids)

	// platform == "github" -> platform filter applied: only the github row
	gh, err := s.getLfsFiles(owner, repo, "github", 1, 10)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a"}, oidsOf(gh))
}

// TestCountLfsFiles_PlatformFilter mirrors the above for the count path, which
// shares the same if/else platform-filter branch and previously reported 0%.
func TestCountLfsFiles_PlatformFilter(t *testing.T) {
	teardown := newSQLiteTestDB(t)
	defer teardown()

	const owner, repo = "mindspore-ai", "repo"
	rows := []db.LfsObj{
		{Oid: "a", Owner: owner, Repo: repo, Platform: "github", Exist: 1, Size: 10},
		{Oid: "b", Owner: owner, Repo: repo, Platform: "gitee", Exist: 1, Size: 20},
		{Oid: "c", Owner: owner, Repo: repo, Platform: "github", Exist: 0, Size: 30},
	}
	for i := range rows {
		require.NoError(t, db.Db.Create(&rows[i]).Error)
	}

	s := &server{}

	totalAll, err := s.countLfsFiles(owner, repo, "")
	require.NoError(t, err)
	assert.Equal(t, int64(2), totalAll, `platform="" must not add a platform filter`)

	totalGh, err := s.countLfsFiles(owner, repo, "github")
	require.NoError(t, err)
	assert.Equal(t, int64(1), totalGh, `platform="github" must narrow to github rows`)
}

func oidsOf(files []db.LfsObj) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Oid)
	}
	return out
}
