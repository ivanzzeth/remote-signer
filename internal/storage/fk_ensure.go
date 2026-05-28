package storage

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// fkSpec describes a foreign key that should exist on an SQLite table.
type fkSpec struct {
	table string
	col   string
	ref   string // "table(col)"
	onDel string // CASCADE, SET NULL, RESTRICT
}

// expectedForeignKeys lists every FK declared via GORM struct tags.
// Grouped by table — tables with multiple FKs are recreated once with
// all FKs so the first FK isn't lost.
var expectedForeignKeys = []fkSpec{
	{table: "rule_budgets", col: "rule_id", ref: "rules(id)", onDel: "CASCADE"},
	{table: "sign_requests", col: "rule_matched_id", ref: "rules(id)", onDel: "SET NULL"},
	{table: "sign_requests", col: "api_key_id", ref: "api_keys(id)", onDel: "RESTRICT"},
	{table: "signer_ownership", col: "owner_id", ref: "api_keys(id)", onDel: "RESTRICT"},
	{table: "wallets", col: "owner_id", ref: "api_keys(id)", onDel: "RESTRICT"},
}

// ensureForeignKeys backfills FK constraints on existing SQLite databases.
func ensureForeignKeys(db *gorm.DB, dsn string) error {
	if !strings.HasPrefix(dsn, "file:") && !strings.HasSuffix(dsn, ".db") {
		return nil
	}

	// Group FKs by table.
	byTable := make(map[string][]fkSpec)
	for _, fk := range expectedForeignKeys {
		byTable[fk.table] = append(byTable[fk.table], fk)
	}

	for tableName, fks := range byTable {
		if err := ensureTableFKs(db, tableName, fks); err != nil {
			return err
		}
	}
	return nil
}

func ensureTableFKs(db *gorm.DB, tableName string, wanted []fkSpec) error {
	// Check table exists.
	var tableCount int64
	if err := db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&tableCount).Error; err != nil {
		return err
	}
	if tableCount == 0 {
		return nil
	}

	// Read existing FKs.
	existing := make(map[string]bool)
	fkRows, err := db.Raw("PRAGMA foreign_key_list(" + quoteIdent(tableName) + ")").Rows()
	if err != nil {
		return err
	}
	defer fkRows.Close()
	for fkRows.Next() {
		var id, seq int
		var refTbl, from, to, onUpdate, onDelete, match string
		if err := fkRows.Scan(&id, &seq, &refTbl, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return err
		}
		existing[from] = true
	}

	// Check which FKs are missing.
	var missing []fkSpec
	for _, fk := range wanted {
		if !existing[fk.col] {
			// Verify referenced table exists.
			refTable := strings.Split(fk.ref, "(")[0]
			var rc int64
			db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", refTable).Scan(&rc)
			if rc == 0 {
				continue
			}
			missing = append(missing, fk)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	// Recreate table with ALL wanted FKs (to keep existing ones too).
	return recreateTableWithAllFKs(db, tableName, wanted)
}

func quoteIdent(s string) string { return `"` + s + `"` }

func recreateTableWithAllFKs(db *gorm.DB, tableName string, allFKs []fkSpec) error {
	// Read column definitions.
	colRows, err := db.Raw("PRAGMA table_info(" + quoteIdent(tableName) + ")").Rows()
	if err != nil {
		return err
	}
	defer colRows.Close()

	type colInfo struct {
		cid       int
		name      string
		typ       string
		notnull   bool
		dfltValue *string
		pk        bool
	}
	var cols []colInfo
	for colRows.Next() {
		var c colInfo
		if err := colRows.Scan(&c.cid, &c.name, &c.typ, &c.notnull, &c.dfltValue, &c.pk); err != nil {
			return err
		}
		cols = append(cols, c)
	}

	// Read index DDL.
	idxRows, err := db.Raw("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", tableName).Rows()
	if err != nil {
		return err
	}
	defer idxRows.Close()
	var indexSQLs []string
	for idxRows.Next() {
		var sql string
		if err := idxRows.Scan(&sql); err != nil {
			return err
		}
		indexSQLs = append(indexSQLs, sql)
	}

	// Build CREATE TABLE.
	newTable := tableName + "_fknew"
	var colDefs []string
	var pkCols []string
	for _, c := range cols {
		def := `"` + c.name + `" ` + c.typ
		if c.notnull && c.dfltValue == nil {
			def += " NOT NULL"
		}
		if c.dfltValue != nil {
			def += " DEFAULT " + *c.dfltValue
		}
		if c.pk {
			pkCols = append(pkCols, c.name)
		}
		colDefs = append(colDefs, def)
	}
	if len(pkCols) > 0 {
		colDefs = append(colDefs, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}
	for _, fk := range allFKs {
		refTable := strings.Split(fk.ref, "(")[0]
		colDefs = append(colDefs, fmt.Sprintf("FOREIGN KEY (%s) REFERENCES %s(id) ON DELETE %s",
			fk.col, refTable, fk.onDel))
	}

	createSQL := "CREATE TABLE " + quoteIdent(newTable) + " (\n    " + strings.Join(colDefs, ",\n    ") + "\n)"

	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
			return err
		}

		if err := tx.Exec(createSQL).Error; err != nil {
			return fmt.Errorf("create new table: %w", err)
		}

		// Clean orphan data for each FK.
		for _, fk := range allFKs {
			refTable := strings.Split(fk.ref, "(")[0]
			if fk.onDel == "SET NULL" || fk.onDel == "CASCADE" {
				tx.Exec("UPDATE " + quoteIdent(tableName) + " SET " + quoteIdent(fk.col) +
					" = NULL WHERE " + quoteIdent(fk.col) + " IS NOT NULL AND " +
					quoteIdent(fk.col) + " NOT IN (SELECT id FROM " + quoteIdent(refTable) + ")")
			} else {
				tx.Exec("DELETE FROM " + quoteIdent(tableName) + " WHERE " +
					quoteIdent(fk.col) + " NOT IN (SELECT id FROM " + quoteIdent(refTable) + ")")
			}
		}

		if err := tx.Exec("INSERT INTO " + quoteIdent(newTable) + " SELECT * FROM " + quoteIdent(tableName)).Error; err != nil {
			return fmt.Errorf("copy rows: %w", err)
		}

		if err := tx.Exec("DROP TABLE " + quoteIdent(tableName)).Error; err != nil {
			return fmt.Errorf("drop old: %w", err)
		}

		if err := tx.Exec("ALTER TABLE " + quoteIdent(newTable) + " RENAME TO " + quoteIdent(tableName)).Error; err != nil {
			return fmt.Errorf("rename: %w", err)
		}

		for _, idxSQL := range indexSQLs {
			if err := tx.Exec(idxSQL).Error; err != nil {
				return fmt.Errorf("recreate index: %w", err)
			}
		}

		if err := tx.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			return err
		}
		return nil
	})
}
