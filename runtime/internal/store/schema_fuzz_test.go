package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"maps"
	"sort"
	"strings"
	"testing"
)

type schemaFuzzErrorKind uint8

const (
	schemaFuzzNoError schemaFuzzErrorKind = iota
	schemaFuzzFutureError
	schemaFuzzUnexpectedError
	schemaFuzzOtherError
)

type schemaFuzzFixture struct {
	version       int64
	forbidden     int64
	tables        map[string]string
	nullStatement bool
}

type schemaFuzzConnector struct {
	fixture schemaFuzzFixture
}

func (connector schemaFuzzConnector) Connect(context.Context) (driver.Conn, error) {
	return &schemaFuzzConnection{fixture: connector.fixture}, nil
}

func (connector schemaFuzzConnector) Driver() driver.Driver {
	return schemaFuzzDriver{}
}

type schemaFuzzDriver struct{}

func (schemaFuzzDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("schema fuzz driver requires its connector")
}

type schemaFuzzConnection struct {
	fixture schemaFuzzFixture
}

func (*schemaFuzzConnection) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}

func (*schemaFuzzConnection) Close() error {
	return nil
}

func (*schemaFuzzConnection) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}

func (connection *schemaFuzzConnection) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	normalizedQuery := strings.Join(strings.Fields(query), " ")
	switch normalizedQuery {
	case "PRAGMA user_version":
		return &schemaFuzzRows{
			columns: []string{"user_version"},
			values:  [][]driver.Value{{connection.fixture.version}},
		}, nil
	case "SELECT count(*) FROM sqlite_schema WHERE type IN ('trigger', 'view') OR (type = 'index' AND sql IS NOT NULL)":
		return &schemaFuzzRows{
			columns: []string{"count(*)"},
			values:  [][]driver.Value{{connection.fixture.forbidden}},
		}, nil
	case "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name":
		names := make([]string, 0, len(connection.fixture.tables))
		for name := range connection.fixture.tables {
			names = append(names, name)
		}
		sort.Strings(names)
		values := make([][]driver.Value, 0, len(names))
		for index, name := range names {
			var statement driver.Value = connection.fixture.tables[name]
			if index == 0 && connection.fixture.nullStatement {
				statement = nil
			}
			values = append(values, []driver.Value{name, statement})
		}
		return &schemaFuzzRows{
			columns: []string{"name", "sql"},
			values:  values,
		}, nil
	default:
		return nil, errors.New("unexpected schema fuzz query")
	}
}

type schemaFuzzRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (rows *schemaFuzzRows) Columns() []string {
	return rows.columns
}

func (*schemaFuzzRows) Close() error {
	return nil
}

func (rows *schemaFuzzRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func cloneSchemaFuzzBase(kind uint8) map[string]string {
	switch kind % 5 {
	case 1:
		return maps.Clone(legacySchemaTables)
	case 2:
		return maps.Clone(priorFullSchemaTables)
	case 3:
		return maps.Clone(priorAcceptanceOriginSchemaTables)
	case 4:
		return maps.Clone(fullSchemaTables)
	default:
		return make(map[string]string)
	}
}

func schemaFuzzVisibleTables(tables map[string]string) map[string]string {
	visible := make(map[string]string, len(tables))
	for name, statement := range tables {
		// SQLite LIKE treats the underscore in sqlite_% as a one-character
		// wildcard, so the production query excludes any seven-or-more-byte
		// name beginning with sqlite.
		if len(name) >= len("sqlite_") && strings.EqualFold(name[:len("sqlite")], "sqlite") {
			continue
		}
		visible[name] = statement
	}
	return visible
}

func mutateSchemaFuzzTables(tables map[string]string, mutation, selector uint8, name, statement string) {
	names := make([]string, 0, len(tables))
	for existing := range tables {
		names = append(names, existing)
	}
	sort.Strings(names)
	selected := ""
	if len(names) != 0 {
		selected = names[int(selector)%len(names)]
	}
	switch mutation % 5 {
	case 0:
		return
	case 1:
		tables[name] = statement
	case 2:
		if selected == "" {
			tables[name] = statement
		} else {
			tables[selected] = statement
		}
	case 3:
		delete(tables, selected)
	case 4:
		if selected == "" {
			tables[name] = statement
		} else {
			selectedStatement := tables[selected]
			delete(tables, selected)
			tables[name] = selectedStatement
		}
	}
}

func classifySchemaFuzzError(err error) schemaFuzzErrorKind {
	switch {
	case err == nil:
		return schemaFuzzNoError
	case errors.Is(err, ErrFutureSchema):
		return schemaFuzzFutureError
	case errors.Is(err, ErrUnexpectedSchema):
		return schemaFuzzUnexpectedError
	default:
		return schemaFuzzOtherError
	}
}

func exactSchemaFuzzInspection(fixture schemaFuzzFixture) (schemaKind, schemaFuzzErrorKind) {
	if fixture.version > SchemaVersion {
		return schemaEmpty, schemaFuzzFutureError
	}
	if fixture.version < 0 {
		return schemaEmpty, schemaFuzzOtherError
	}
	if fixture.forbidden != 0 {
		return schemaEmpty, schemaFuzzUnexpectedError
	}
	if fixture.nullStatement && len(fixture.tables) != 0 {
		return schemaEmpty, schemaFuzzOtherError
	}
	if fixture.version == 0 {
		if len(fixture.tables) == 0 {
			return schemaEmpty, schemaFuzzNoError
		}
		return schemaEmpty, schemaFuzzUnexpectedError
	}
	for _, candidate := range []struct {
		kind   schemaKind
		tables map[string]string
	}{
		{kind: schemaFull, tables: fullSchemaTables},
		{kind: schemaPriorAcceptanceOrigin, tables: priorAcceptanceOriginSchemaTables},
		{kind: schemaPriorFull, tables: priorFullSchemaTables},
		{kind: schemaLegacy, tables: legacySchemaTables},
	} {
		if maps.Equal(fixture.tables, candidate.tables) {
			return candidate.kind, schemaFuzzNoError
		}
	}
	return schemaEmpty, schemaFuzzUnexpectedError
}

func FuzzSQLiteSchemaState(f *testing.F) {
	for base := uint8(0); base < 5; base++ {
		version := int32(SchemaVersion)
		if base == 0 {
			version = 0
		}
		f.Add(version, base, uint8(0), uint8(0), uint8(0), "", "")
	}
	f.Add(int32(-1), uint8(0), uint8(0), uint8(0), uint8(0), "", "")
	f.Add(int32(SchemaVersion+1), uint8(4), uint8(0), uint8(0), uint8(0), "", "")
	f.Add(int32(SchemaVersion), uint8(4), uint8(1), uint8(0), uint8(0), "unexpected", "CREATE TABLE unexpected (value TEXT)")
	f.Add(int32(SchemaVersion), uint8(4), uint8(2), uint8(0), uint8(0), "", "CREATE TABLE devices (device_id TEXT)")
	f.Add(int32(SchemaVersion), uint8(4), uint8(0), uint8(0), uint8(1), "", "")
	f.Add(int32(SchemaVersion), uint8(4), uint8(0), uint8(0), uint8(4), "", "")

	f.Fuzz(func(t *testing.T, version int32, base, mutation, selector, auxiliary uint8, name, statement string) {
		if len(name) > 256 || len(statement) > 256 {
			return
		}
		tables := cloneSchemaFuzzBase(base)
		mutateSchemaFuzzTables(tables, mutation, selector, name, statement)
		fixture := schemaFuzzFixture{
			version:       int64(version),
			forbidden:     int64(auxiliary & 0x3),
			tables:        schemaFuzzVisibleTables(tables),
			nullStatement: auxiliary&0x4 != 0,
		}
		database := sql.OpenDB(schemaFuzzConnector{fixture: fixture})
		database.SetMaxOpenConns(1)
		database.SetMaxIdleConns(1)
		defer database.Close()

		ctx := context.Background()
		gotKind, gotVersion, gotErr := inspectSchemaState(ctx, database)
		wantKind, wantErrKind := exactSchemaFuzzInspection(fixture)
		if gotKind != wantKind || gotVersion != int(version) || classifySchemaFuzzError(gotErr) != wantErrKind {
			t.Fatalf(
				"schema inspection=(kind=%d version=%d error=%d), exact oracle=(kind=%d version=%d error=%d)",
				gotKind,
				gotVersion,
				classifySchemaFuzzError(gotErr),
				wantKind,
				version,
				wantErrKind,
			)
		}

		validatedVersion, validateErr := validateSchemaState(ctx, database)
		wantValidateErr := wantErrKind
		if wantValidateErr == schemaFuzzNoError && version != 0 && wantKind != schemaFull {
			wantValidateErr = schemaFuzzUnexpectedError
		}
		if validatedVersion != int(version) || classifySchemaFuzzError(validateErr) != wantValidateErr {
			t.Fatalf(
				"schema validation=(version=%d error=%d), exact oracle=(version=%d error=%d)",
				validatedVersion,
				classifySchemaFuzzError(validateErr),
				version,
				wantValidateErr,
			)
		}

		readTables, readErr := readSchemaTables(ctx, database)
		wantReadErr := schemaFuzzNoError
		if fixture.forbidden != 0 {
			wantReadErr = schemaFuzzUnexpectedError
		} else if fixture.nullStatement && len(fixture.tables) != 0 {
			wantReadErr = schemaFuzzOtherError
		}
		if classifySchemaFuzzError(readErr) != wantReadErr || readErr == nil && !maps.Equal(readTables, fixture.tables) {
			t.Fatalf("schema table read error=%d tables_equal=%t, exact oracle error=%d", classifySchemaFuzzError(readErr), maps.Equal(readTables, fixture.tables), wantReadErr)
		}

		for _, expected := range []map[string]string{
			fullSchemaTables,
			priorAcceptanceOriginSchemaTables,
			priorFullSchemaTables,
			legacySchemaTables,
			{},
		} {
			if got, want := schemaTablesEqual(fixture.tables, expected), maps.Equal(fixture.tables, expected); got != want {
				t.Fatalf("schemaTablesEqual=%t, exact map oracle=%t", got, want)
			}
		}
	})
}
