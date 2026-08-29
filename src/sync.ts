import { WhoopClient } from './whoop-client.js';
import { WhoopDatabase, type UpsertResult } from './database.js';

interface SyncStats {
	cycles: number;
	recoveries: number;
	sleeps: number;
	workouts: number;
	/** Records whose mapping threw; they were logged and skipped, not stored. */
	skipped: number;
}

const NO_ROWS: UpsertResult = { upserted: 0, skipped: 0 };

interface SmartSyncResult {
	type: 'full' | 'quick' | 'skip';
	stats?: SyncStats;
}

export class WhoopSync {
	private readonly client: WhoopClient;
	private readonly db: WhoopDatabase;

	constructor(client: WhoopClient, db: WhoopDatabase) {
		this.client = client;
		this.db = db;
	}

	async syncDays(days = 90): Promise<SyncStats> {
		const endDate = new Date();
		const startDate = new Date();
		startDate.setDate(startDate.getDate() - days);

		// A record fetched while still PENDING_SCORE carries no score. Whoop fills
		// it in hours later, so unless the window reaches back to the oldest
		// pending record it stays permanently unscored -- the 7-day quick sync
		// would otherwise walk straight past it.
		const oldestPending = this.db.getOldestPendingScoreDate();
		if (oldestPending) {
			const pendingStart = new Date(oldestPending);
			if (!Number.isNaN(pendingStart.getTime()) && pendingStart < startDate) {
				// A day of slack absorbs timezone_offset skew at the boundary.
				pendingStart.setDate(pendingStart.getDate() - 1);
				startDate.setTime(pendingStart.getTime());
				console.error(
					`[whoop] widened sync window back to ${startDate.toISOString()} to re-fetch PENDING_SCORE records`
				);
			}
		}

		const start = startDate.toISOString();
		const end = endDate.toISOString();

		// Rotate once, up front. The four fetches below run concurrently and would
		// otherwise each discover the same expiring token and race to refresh it.
		// The client single-flights that race safely, but doing it here keeps the
		// contention out of the fan-out entirely.
		await this.client.ensureAuthenticated();

		const [cycles, recoveries, sleeps, workouts] = await Promise.all([
			this.client.getAllCycles({ start, end }),
			this.client.getAllRecoveries({ start, end }),
			this.client.getAllSleeps({ start, end }),
			this.client.getAllWorkouts({ start, end }),
		]);

		// INSERT OR REPLACE means a re-fetched record overwrites its unscored row.
		const cycleRows = cycles.length > 0 ? this.db.upsertCycles(cycles) : NO_ROWS;
		const recoveryRows = recoveries.length > 0 ? this.db.upsertRecoveries(recoveries) : NO_ROWS;
		const sleepRows = sleeps.length > 0 ? this.db.upsertSleeps(sleeps) : NO_ROWS;
		const workoutRows = workouts.length > 0 ? this.db.upsertWorkouts(workouts) : NO_ROWS;

		this.db.updateSyncState(
			startDate.toISOString().split('T')[0],
			endDate.toISOString().split('T')[0]
		);

		const skipped = cycleRows.skipped + recoveryRows.skipped + sleepRows.skipped + workoutRows.skipped;
		if (skipped > 0) {
			console.error(`[whoop] sync finished with ${skipped} record(s) skipped; see the entries above`);
		}

		return {
			cycles: cycleRows.upserted,
			recoveries: recoveryRows.upserted,
			sleeps: sleepRows.upserted,
			workouts: workoutRows.upserted,
			skipped,
		};
	}

	async quickSync(): Promise<SyncStats> {
		return this.syncDays(7);
	}

	needsFullSync(): boolean {
		const state = this.db.getSyncState();
		if (!state.lastSyncAt) return true;

		const lastSync = new Date(state.lastSyncAt);
		const hoursSinceSync = (Date.now() - lastSync.getTime()) / (1000 * 60 * 60);
		return hoursSinceSync > 24;
	}

	async smartSync(): Promise<SmartSyncResult> {
		const state = this.db.getSyncState();

		if (!state.lastSyncAt) {
			const stats = await this.syncDays(90);
			return { type: 'full', stats };
		}

		const lastSync = new Date(state.lastSyncAt);
		const hoursSinceSync = (Date.now() - lastSync.getTime()) / (1000 * 60 * 60);

		// Never skip while something is still unscored: the whole point of coming
		// back is to pick up the score Whoop has since computed.
		if (hoursSinceSync < 1 && this.db.countPendingScoreRecords() === 0) {
			return { type: 'skip' };
		}

		const stats = await this.quickSync();
		return { type: 'quick', stats };
	}
}
