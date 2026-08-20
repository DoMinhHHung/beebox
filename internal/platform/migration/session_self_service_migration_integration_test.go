//go:build integration

package migration

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSessionSelfServiceMigrationUpgradesExactVersion21AndAddsListIndex(t *testing.T) {
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_session_self_service_migration"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	throughTwentyOne := migrationSourcesThrough(t, 21)
	if err := upWithSources(ctx, pool.OpenSQLDB(), throughTwentyOne); err != nil {
		t.Fatalf("apply exact version 21 schema: %v", err)
	}
	assertMigrationState(t, ctx, pool, 21)

	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO application_instances(public_id) VALUES ('app_123e4567-e89b-42d3-a456-426614175101');
		INSERT INTO users(public_id,application_instance_id)
		SELECT 'usr_123e4567-e89b-42d3-a456-426614175102',id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175101';
		INSERT INTO sessions(public_id,application_instance_id,user_id,created_at,last_seen_at,idle_expires_at,expires_at)
		SELECT 'ses_123e4567-e89b-42d3-a456-426614175103',u.application_instance_id,u.id,CURRENT_TIMESTAMP-INTERVAL '2 minutes',CURRENT_TIMESTAMP-INTERVAL '1 minute',CURRENT_TIMESTAMP+INTERVAL '1 hour',CURRENT_TIMESTAMP+INTERVAL '2 hours'
		FROM users u WHERE u.public_id='usr_123e4567-e89b-42d3-a456-426614175102'`); err != nil {
		t.Fatal(err)
	}

	onlyTwentyTwo := migrationSourcesRange(t, 22, 22)
	if err := upWithSources(ctx, pool.OpenSQLDB(), onlyTwentyTwo); err != nil {
		t.Fatalf("upgrade exact 21 -> 22: %v", err)
	}
	assertMigrationState(t, ctx, pool, 22)

	var indexDef string
	if err := db.QueryRowContext(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='sessions_self_service_list_idx'`).Scan(&indexDef); err != nil {
		t.Fatalf("read self-service index: %v", err)
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(indexDef)), " ")
	for _, want := range []string{"application_instance_id", "user_id", "created_at desc", "public_id desc"} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("index definition %q missing %q", indexDef, want)
		}
	}

	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id='ses_123e4567-e89b-42d3-a456-426614175103'`).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("predecessor session count=%d err=%v", sessions, err)
	}

	if _, err := db.ExecContext(ctx, `SET enable_seqscan=off`); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, `
		EXPLAIN (COSTS OFF)
		SELECT public_id FROM sessions
		WHERE application_instance_id=(SELECT id FROM application_instances WHERE public_id='app_123e4567-e89b-42d3-a456-426614175101')
		  AND user_id=(SELECT id FROM users WHERE public_id='usr_123e4567-e89b-42d3-a456-426614175102')
		ORDER BY created_at DESC,public_id DESC LIMIT 21`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "sessions_self_service_list_idx") {
		t.Fatalf("self-service access plan does not use ordered index:\n%s", plan.String())
	}
}
