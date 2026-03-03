package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectDialector_SQLite_FilePrefix(t *testing.T) {
	d, err := detectDialector("file::memory:")
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestDetectDialector_SQLite_DbSuffix(t *testing.T) {
	d, err := detectDialector("test.db")
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestDetectDialector_Postgres_PostgresPrefix(t *testing.T) {
	d, err := detectDialector("postgres://user:pass@localhost/db")
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestDetectDialector_Postgres_PostgresqlPrefix(t *testing.T) {
	d, err := detectDialector("postgresql://user:pass@localhost/db")
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestDetectDialector_Default_FallsBackToPostgres(t *testing.T) {
	// Unrecognized DSN defaults to postgres
	d, err := detectDialector("some-random-dsn")
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestNewDB_EmptyDSN(t *testing.T) {
	db, err := NewDB(Config{DSN: ""})
	assert.Nil(t, db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database DSN is required")
}

func TestNewDB_SQLiteInMemory(t *testing.T) {
	db, err := NewDB(Config{DSN: "file::memory:"})
	require.NoError(t, err)
	assert.NotNil(t, db)
}

func TestNewDBWithLogger_EmptyDSN(t *testing.T) {
	db, err := NewDBWithLogger(Config{DSN: ""}, 0)
	assert.Nil(t, db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database DSN is required")
}

func TestNewDBWithLogger_SQLiteInMemory(t *testing.T) {
	db, err := NewDBWithLogger(Config{DSN: "file::memory:"}, 1)
	require.NoError(t, err)
	assert.NotNil(t, db)
}
