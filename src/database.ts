import Database from 'better-sqlite3';
import { encrypt, decrypt, isEncrypted } from './crypto.js';
import type {
	WhoopTokens,
	WhoopCycle,
	WhoopRecovery,
	WhoopSleep,
	WhoopWorkout,
	WhoopZoneDurations,
	DbCycle,
	DbRecovery,
	DbSleep,
	DbWorkout,
} from './types.js';

interface TokenRow {
	id: number;
	access_token: string;
	refresh_token: string;
	expires_at: number;
	updated_at: string;
}

interface SyncStateRow {
	id: number;
	last_sync_at: string | null;
	oldest_synced_date: string | null;
	newest_synced_date: string | null;
}

interface RecoveryTrendRow {
	date: string;
	recovery_score: number;
	hrv: number;
	rhr: number;
}

interface SleepTrendRow {
	date: string;
	total_sleep_hours: number;
	performance: number;
	efficiency: number;
}

interface StrainTrendRow {
	date: string;
	strain: number;
	calories: number;
}

export interface OAuthClient {
	client_id: string;
	client_secret: string | null;
	client_name: string | null;
	redirect_uris: string[];
	created_at: string;
}

export interface OAuthAuthCode {
	code: string;
	client_id: string;
	redirect_uri: string;
	code_challenge: string;
	code_challenge_method: string;
	scope: string | null;
	expires_at: number;
}

export interface OAuthAccessToken {
	access_token: string;
	refresh_token: string;
	client_id: string;
	expires_at: number;
	scope: string | null;
}

interface OAuthClientRow {
	client_id: string;
	client_secret: string | null;
	client_name: string | null;
	redirect_uris: string;
	created_at: string;
}

interface OAuthAuthCodeRow {
	code: string;
	client_id: string;
	redirect_uri: string;
	code_challenge: string;
	code_challenge_method: string;
	scope: string | null;
	expires_at: number;
}

interface OAuthAccessTokenRow {
	access_token: string;
	refresh_token: string;
	client_id: string;
	expires_at: number;
	scope: string | null;
}

export interface UpsertResult {
	upserted: number;
	skipped: number;
}

/**
 * A single malformed record must not take the whole sync down with it, so every
 * row is mapped inside its own try/catch and failures are reported here.
 */
/**
 * Whoop v2 returns the heart-rate zone breakdown as score.zone_durations.
 * The v1 singular spelling is accepted as a fallback; reading a path that does
 * not exist yields undefined, which is how every zone column silently became
 * null before this was corrected.
 */
function workoutZones(score: WhoopWorkout['score']): WhoopZoneDurations | undefined {
	return score?.zone_durations ?? score?.zone_duration;
}

function logSkippedRecord(kind: string, id: string | number | undefined, error: unknown): void {
	const reason = error instanceof Error ? error.message : String(error);
	console.error(`[whoop] skipped ${kind} record ${id ?? '(no id)'} during sync: ${reason}`);
}

export class WhoopDatabase {
	private db: Database.Database;

	constructor(dbPath = './whoop.db') {
		this.db = new Database(dbPath);
		this.db.pragma('journal_mode = WAL');
		this.initSchema();
	}

	private initSchema(): void {
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS tokens (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				access_token TEXT NOT NULL,
				refresh_token TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				updated_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS sync_state (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				last_sync_at TEXT,
				oldest_synced_date TEXT,
				newest_synced_date TEXT
			);

			CREATE TABLE IF NOT EXISTS cycles (
				id INTEGER PRIMARY KEY,
				user_id INTEGER NOT NULL,
				start_time TEXT NOT NULL,
				end_time TEXT,
				score_state TEXT NOT NULL,
				strain REAL,
				kilojoule REAL,
				avg_hr INTEGER,
				max_hr INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS recovery (
				id INTEGER PRIMARY KEY,
				user_id INTEGER NOT NULL,
				sleep_id TEXT,
				created_at TEXT NOT NULL,
				score_state TEXT NOT NULL,
				recovery_score INTEGER,
				resting_hr INTEGER,
				hrv_rmssd REAL,
				spo2 REAL,
				skin_temp REAL,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS sleep (
				id TEXT PRIMARY KEY,
				user_id INTEGER NOT NULL,
				cycle_id INTEGER,
				start_time TEXT NOT NULL,
				end_time TEXT NOT NULL,
				is_nap INTEGER NOT NULL DEFAULT 0,
				score_state TEXT NOT NULL,
				total_in_bed_milli INTEGER,
				total_awake_milli INTEGER,
				total_light_milli INTEGER,
				total_deep_milli INTEGER,
				total_rem_milli INTEGER,
				sleep_performance REAL,
				sleep_efficiency REAL,
				sleep_consistency REAL,
				respiratory_rate REAL,
				sleep_needed_baseline_milli INTEGER,
				sleep_needed_debt_milli INTEGER,
				sleep_needed_strain_milli INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS workouts (
				id TEXT PRIMARY KEY,
				user_id INTEGER NOT NULL,
				sport_id INTEGER NOT NULL,
				start_time TEXT NOT NULL,
				end_time TEXT NOT NULL,
				score_state TEXT NOT NULL,
				strain REAL,
				avg_hr INTEGER,
				max_hr INTEGER,
				kilojoule REAL,
				zone_zero_milli INTEGER,
				zone_one_milli INTEGER,
				zone_two_milli INTEGER,
				zone_three_milli INTEGER,
				zone_four_milli INTEGER,
				zone_five_milli INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE INDEX IF NOT EXISTS idx_cycles_start ON cycles(start_time);
			CREATE INDEX IF NOT EXISTS idx_recovery_created ON recovery(created_at);
			CREATE INDEX IF NOT EXISTS idx_sleep_start ON sleep(start_time);
			CREATE INDEX IF NOT EXISTS idx_workouts_start ON workouts(start_time);

			CREATE TABLE IF NOT EXISTS oauth_clients (
				client_id TEXT PRIMARY KEY,
				client_secret TEXT,
				client_name TEXT,
				redirect_uris TEXT NOT NULL,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS oauth_auth_codes (
				code TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				redirect_uri TEXT NOT NULL,
				code_challenge TEXT NOT NULL,
				code_challenge_method TEXT NOT NULL,
				scope TEXT,
				expires_at INTEGER NOT NULL
			);

			CREATE TABLE IF NOT EXISTS oauth_access_tokens (
				access_token TEXT PRIMARY KEY,
				refresh_token TEXT UNIQUE NOT NULL,
				client_id TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				scope TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh ON oauth_access_tokens(refresh_token);

			INSERT OR IGNORE INTO sync_state (id) VALUES (1);
		`);
	}

	saveTokens(tokens: WhoopTokens): void {
		const encryptedAccess = encrypt(tokens.access_token);
		const encryptedRefresh = encrypt(tokens.refresh_token);

		this.db.prepare(`
			INSERT OR REPLACE INTO tokens (id, access_token, refresh_token, expires_at, updated_at)
			VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		`).run(encryptedAccess, encryptedRefresh, tokens.expires_at);
	}

	getTokens(): WhoopTokens | null {
		const row = this.db.prepare('SELECT * FROM tokens WHERE id = 1').get() as TokenRow | undefined;
		if (!row) return null;

		const accessToken = isEncrypted(row.access_token)
			? decrypt(row.access_token)
			: row.access_token;

		const refreshToken = isEncrypted(row.refresh_token)
			? decrypt(row.refresh_token)
			: row.refresh_token;

		return {
			access_token: accessToken,
			refresh_token: refreshToken,
			expires_at: row.expires_at,
		};
	}

	getSyncState(): { lastSyncAt: string | null; oldestDate: string | null; newestDate: string | null } {
		const row = this.db.prepare('SELECT * FROM sync_state WHERE id = 1').get() as SyncStateRow | undefined;
		return {
			lastSyncAt: row?.last_sync_at ?? null,
			oldestDate: row?.oldest_synced_date ?? null,
			newestDate: row?.newest_synced_date ?? null,
		};
	}

	updateSyncState(oldestDate: string, newestDate: string): void {
		this.db.prepare(`
			UPDATE sync_state
			SET last_sync_at = CURRENT_TIMESTAMP,
				oldest_synced_date = COALESCE(
					CASE WHEN oldest_synced_date IS NULL OR ? < oldest_synced_date THEN ? ELSE oldest_synced_date END,
					?
				),
				newest_synced_date = COALESCE(
					CASE WHEN newest_synced_date IS NULL OR ? > newest_synced_date THEN ? ELSE newest_synced_date END,
					?
				)
			WHERE id = 1
		`).run(oldestDate, oldestDate, oldestDate, newestDate, newestDate, newestDate);
	}

	upsertCycles(cycles: WhoopCycle[]): UpsertResult {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO cycles (
				id, user_id, start_time, end_time, score_state, strain, kilojoule, avg_hr, max_hr,
				synced_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		return this.db.transaction((items: WhoopCycle[]): UpsertResult => {
			const result: UpsertResult = { upserted: 0, skipped: 0 };
			for (const c of items) {
				try {
					stmt.run(
						c.id,
						c.user_id,
						c.start,
						c.end ?? null,
						c.score_state,
						c.score?.strain ?? null,
						c.score?.kilojoule ?? null,
						c.score?.average_heart_rate ?? null,
						c.score?.max_heart_rate ?? null
					);
					result.upserted++;
				} catch (error) {
					result.skipped++;
					logSkippedRecord('cycle', c.id, error);
				}
			}
			return result;
		})(cycles);
	}

	upsertRecoveries(recoveries: WhoopRecovery[]): UpsertResult {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO recovery (
				id, user_id, sleep_id, created_at, score_state, recovery_score, resting_hr, hrv_rmssd, spo2, skin_temp,
				synced_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		return this.db.transaction((items: WhoopRecovery[]): UpsertResult => {
			const result: UpsertResult = { upserted: 0, skipped: 0 };
			for (const r of items) {
				try {
					stmt.run(
						r.cycle_id,
						r.user_id,
						r.sleep_id ?? null,
						r.created_at,
						r.score_state,
						r.score?.recovery_score ?? null,
						r.score?.resting_heart_rate ?? null,
						r.score?.hrv_rmssd_milli ?? null,
						r.score?.spo2_percentage ?? null,
						r.score?.skin_temp_celsius ?? null
					);
					result.upserted++;
				} catch (error) {
					result.skipped++;
					logSkippedRecord('recovery', r.cycle_id, error);
				}
			}
			return result;
		})(recoveries);
	}

	upsertSleeps(sleeps: WhoopSleep[]): UpsertResult {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO sleep (
				id, user_id, start_time, end_time, is_nap, score_state,
				total_in_bed_milli, total_awake_milli, total_light_milli, total_deep_milli, total_rem_milli,
				sleep_performance, sleep_efficiency, sleep_consistency, respiratory_rate,
				sleep_needed_baseline_milli, sleep_needed_debt_milli, sleep_needed_strain_milli,
				synced_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		return this.db.transaction((items: WhoopSleep[]): UpsertResult => {
			const result: UpsertResult = { upserted: 0, skipped: 0 };
			for (const s of items) {
				try {
					stmt.run(
						s.id,
						s.user_id,
						s.start,
						s.end,
						s.nap ? 1 : 0,
						s.score_state,
						s.score?.stage_summary?.total_in_bed_time_milli ?? null,
						s.score?.stage_summary?.total_awake_time_milli ?? null,
						s.score?.stage_summary?.total_light_sleep_time_milli ?? null,
						s.score?.stage_summary?.total_slow_wave_sleep_time_milli ?? null,
						s.score?.stage_summary?.total_rem_sleep_time_milli ?? null,
						s.score?.sleep_performance_percentage ?? null,
						s.score?.sleep_efficiency_percentage ?? null,
						s.score?.sleep_consistency_percentage ?? null,
						s.score?.respiratory_rate ?? null,
						s.score?.sleep_needed?.baseline_milli ?? null,
						s.score?.sleep_needed?.need_from_sleep_debt_milli ?? null,
						s.score?.sleep_needed?.need_from_recent_strain_milli ?? null
					);
					result.upserted++;
				} catch (error) {
					result.skipped++;
					logSkippedRecord('sleep', s.id, error);
				}
			}
			return result;
		})(sleeps);
	}

	upsertWorkouts(workouts: WhoopWorkout[]): UpsertResult {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO workouts (
				id, user_id, sport_id, start_time, end_time, score_state,
				strain, avg_hr, max_hr, kilojoule,
				zone_zero_milli, zone_one_milli, zone_two_milli, zone_three_milli, zone_four_milli, zone_five_milli,
				synced_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		return this.db.transaction((items: WhoopWorkout[]): UpsertResult => {
			const result: UpsertResult = { upserted: 0, skipped: 0 };
			for (const w of items) {
				try {
					const zones = workoutZones(w.score);
					if (!zones && w.score && w.score_state === 'SCORED') {
						// Tripwire: a scored workout with no zone object means the API shape
						// moved again. Better a loud log than six more columns of null.
						console.error(
							`[whoop] workout ${w.id} is SCORED but has no zone durations; score keys: ${Object.keys(w.score).join(', ')}`
						);
					}
					stmt.run(
						w.id,
						w.user_id,
						w.sport_id,
						w.start,
						w.end,
						w.score_state,
						w.score?.strain ?? null,
						w.score?.average_heart_rate ?? null,
						w.score?.max_heart_rate ?? null,
						w.score?.kilojoule ?? null,
						zones?.zone_zero_milli ?? null,
						zones?.zone_one_milli ?? null,
						zones?.zone_two_milli ?? null,
						zones?.zone_three_milli ?? null,
						zones?.zone_four_milli ?? null,
						zones?.zone_five_milli ?? null
					);
					result.upserted++;
				} catch (error) {
					result.skipped++;
					logSkippedRecord('workout', w.id, error);
				}
			}
			return result;
		})(workouts);
	}

	/**
	 * Oldest record still awaiting a score, as an ISO timestamp. A sync window
	 * that does not reach this far back will never pick the score up.
	 */
	getOldestPendingScoreDate(): string | null {
		const row = this.db.prepare(`
			SELECT MIN(d) AS oldest FROM (
				SELECT MIN(start_time) AS d FROM cycles   WHERE score_state = 'PENDING_SCORE'
				UNION ALL
				SELECT MIN(created_at) AS d FROM recovery WHERE score_state = 'PENDING_SCORE'
				UNION ALL
				SELECT MIN(start_time) AS d FROM sleep    WHERE score_state = 'PENDING_SCORE'
				UNION ALL
				SELECT MIN(start_time) AS d FROM workouts WHERE score_state = 'PENDING_SCORE'
			)
		`).get() as { oldest: string | null } | undefined;
		return row?.oldest ?? null;
	}

	countPendingScoreRecords(): number {
		const row = this.db.prepare(`
			SELECT
				(SELECT COUNT(*) FROM cycles   WHERE score_state = 'PENDING_SCORE') +
				(SELECT COUNT(*) FROM recovery WHERE score_state = 'PENDING_SCORE') +
				(SELECT COUNT(*) FROM sleep    WHERE score_state = 'PENDING_SCORE') +
				(SELECT COUNT(*) FROM workouts WHERE score_state = 'PENDING_SCORE') AS pending
		`).get() as { pending: number } | undefined;
		return row?.pending ?? 0;
	}

	getLatestCycle(): DbCycle | null {
		return this.db.prepare('SELECT * FROM cycles ORDER BY start_time DESC LIMIT 1').get() as DbCycle | undefined ?? null;
	}

	getLatestRecovery(): DbRecovery | null {
		return this.db.prepare('SELECT * FROM recovery ORDER BY created_at DESC LIMIT 1').get() as DbRecovery | undefined ?? null;
	}

	getLatestSleep(): DbSleep | null {
		return this.db.prepare('SELECT * FROM sleep WHERE is_nap = 0 ORDER BY start_time DESC LIMIT 1').get() as DbSleep | undefined ?? null;
	}

	getCyclesByDateRange(startDate: string, endDate: string): DbCycle[] {
		return this.db.prepare(`
			SELECT * FROM cycles WHERE start_time >= ? AND start_time <= ? ORDER BY start_time DESC
		`).all(startDate, endDate) as DbCycle[];
	}

	getRecoveriesByDateRange(startDate: string, endDate: string): DbRecovery[] {
		return this.db.prepare(`
			SELECT * FROM recovery WHERE created_at >= ? AND created_at <= ? ORDER BY created_at DESC
		`).all(startDate, endDate) as DbRecovery[];
	}

	getSleepsByDateRange(startDate: string, endDate: string, includeNaps = false): DbSleep[] {
		const query = includeNaps
			? 'SELECT * FROM sleep WHERE start_time >= ? AND start_time <= ? ORDER BY start_time DESC'
			: 'SELECT * FROM sleep WHERE start_time >= ? AND start_time <= ? AND is_nap = 0 ORDER BY start_time DESC';
		return this.db.prepare(query).all(startDate, endDate) as DbSleep[];
	}

	getWorkoutsByDateRange(startDate: string, endDate: string): DbWorkout[] {
		return this.db.prepare(`
			SELECT * FROM workouts WHERE start_time >= ? AND start_time <= ? ORDER BY start_time DESC
		`).all(startDate, endDate) as DbWorkout[];
	}

	/**
	 * Workouts started within the last `days` days, newest first. Rows come back
	 * whatever their score_state, so an unscored workout still appears with null
	 * metrics instead of vanishing from the report.
	 */
	getRecentWorkouts(days: number): DbWorkout[] {
		return this.db.prepare(`
			SELECT * FROM workouts
			WHERE start_time >= DATE('now', '-' || ? || ' days')
			ORDER BY start_time DESC
		`).all(days) as DbWorkout[];
	}

	getRecoveryTrends(days: number): RecoveryTrendRow[] {
		return this.db.prepare(`
			SELECT DATE(created_at) as date, recovery_score, hrv_rmssd as hrv, resting_hr as rhr
			FROM recovery
			WHERE recovery_score IS NOT NULL AND created_at >= DATE('now', '-' || ? || ' days')
			ORDER BY created_at DESC
		`).all(days) as RecoveryTrendRow[];
	}

	getSleepTrends(days: number): SleepTrendRow[] {
		return this.db.prepare(`
			SELECT DATE(start_time) as date,
				ROUND((total_in_bed_milli - total_awake_milli) / 3600000.0, 2) as total_sleep_hours,
				sleep_performance as performance, sleep_efficiency as efficiency
			FROM sleep
			WHERE is_nap = 0 AND sleep_performance IS NOT NULL AND start_time >= DATE('now', '-' || ? || ' days')
			ORDER BY start_time DESC
		`).all(days) as SleepTrendRow[];
	}

	getStrainTrends(days: number): StrainTrendRow[] {
		return this.db.prepare(`
			SELECT DATE(start_time) as date, strain, ROUND(kilojoule / 4.184, 0) as calories
			FROM cycles
			WHERE strain IS NOT NULL AND start_time >= DATE('now', '-' || ? || ' days')
			ORDER BY start_time DESC
		`).all(days) as StrainTrendRow[];
	}

	createOAuthClient(input: { client_id: string; client_secret: string | null; client_name: string | null; redirect_uris: string[] }): OAuthClient {
		this.db.prepare(`
			INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris)
			VALUES (?, ?, ?, ?)
		`).run(input.client_id, input.client_secret, input.client_name, JSON.stringify(input.redirect_uris));

		const row = this.db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(input.client_id) as OAuthClientRow;
		return { ...row, redirect_uris: JSON.parse(row.redirect_uris) as string[] };
	}

	getOAuthClient(clientId: string): OAuthClient | null {
		const row = this.db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId) as OAuthClientRow | undefined;
		if (!row) return null;
		return { ...row, redirect_uris: JSON.parse(row.redirect_uris) as string[] };
	}

	createOAuthCode(input: OAuthAuthCode): void {
		this.db.prepare(`
			INSERT INTO oauth_auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`).run(input.code, input.client_id, input.redirect_uri, input.code_challenge, input.code_challenge_method, input.scope, input.expires_at);
	}

	consumeOAuthCode(code: string): OAuthAuthCode | null {
		return this.db.transaction((c: string): OAuthAuthCode | null => {
			const row = this.db.prepare('SELECT * FROM oauth_auth_codes WHERE code = ?').get(c) as OAuthAuthCodeRow | undefined;
			if (!row) return null;
			this.db.prepare('DELETE FROM oauth_auth_codes WHERE code = ?').run(c);
			if (row.expires_at < Date.now()) return null;
			return row;
		})(code);
	}

	createOAuthToken(input: OAuthAccessToken): void {
		this.db.prepare(`
			INSERT INTO oauth_access_tokens (access_token, refresh_token, client_id, expires_at, scope)
			VALUES (?, ?, ?, ?, ?)
		`).run(input.access_token, input.refresh_token, input.client_id, input.expires_at, input.scope);
	}

	getOAuthAccessToken(accessToken: string): OAuthAccessToken | null {
		const row = this.db.prepare('SELECT * FROM oauth_access_tokens WHERE access_token = ?').get(accessToken) as OAuthAccessTokenRow | undefined;
		if (!row) return null;
		if (row.expires_at < Date.now()) return null;
		return row;
	}

	consumeRefreshToken(refreshToken: string): OAuthAccessToken | null {
		return this.db.transaction((rt: string): OAuthAccessToken | null => {
			const row = this.db.prepare('SELECT * FROM oauth_access_tokens WHERE refresh_token = ?').get(rt) as OAuthAccessTokenRow | undefined;
			if (!row) return null;
			this.db.prepare('DELETE FROM oauth_access_tokens WHERE access_token = ?').run(row.access_token);
			return row;
		})(refreshToken);
	}

	close(): void {
		this.db.close();
	}
}
