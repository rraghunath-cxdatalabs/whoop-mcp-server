import { createHash } from 'node:crypto';

import type {
	WhoopTokens,
	WhoopUser,
	WhoopBodyMeasurement,
	WhoopCycle,
	WhoopRecovery,
	WhoopSleep,
	WhoopWorkout,
	WhoopPaginatedResponse,
} from './types.js';

const WHOOP_API_BASE = 'https://api.prod.whoop.com/developer';
const WHOOP_AUTH_BASE = 'https://api.prod.whoop.com/oauth/oauth2';

/** Refresh this long before the access token actually expires. */
const REFRESH_SKEW_MS = 5 * 60 * 1000;

let rawWorkoutLogged = false;
let refreshAttemptCounter = 0;

/**
 * A short, stable digest of a secret. Enough to tell across log lines whether
 * two requests carried the same refresh token -- which is exactly what a replay
 * looks like -- without ever writing the token itself to a log.
 */
function fingerprint(secret: string): string {
	return `sha256:${createHash('sha256').update(secret).digest('hex').slice(0, 12)} len=${secret.length}`;
}

const SECRET_PARAMS = new Set(['refresh_token', 'client_secret', 'code', 'access_token']);

/**
 * Render a token-endpoint body for logging: every parameter name and order is
 * preserved verbatim so a malformed request is visible, while secret values are
 * replaced by a fingerprint. Parameter presence, spelling and duplication are
 * what actually break OAuth requests, and they all survive this.
 */
function describeBody(body: URLSearchParams): string {
	const parts: string[] = [];
	for (const [key, value] of body) {
		if (SECRET_PARAMS.has(key)) parts.push(`${key}=<${fingerprint(value)}>`);
		else if (key === 'client_id') parts.push(`${key}=...${value.slice(-4)}`);
		else parts.push(`${key}=${value}`);
	}
	return parts.join('&');
}

/** Mask any run long enough to plausibly be a token. */
function maskSecretish(text: string): string {
	return text.replace(/[A-Za-z0-9._~+/=-]{20,}/g, '<masked>');
}

/**
 * Render a token-endpoint response for logging. A success body carries live
 * credentials and an error body sometimes echoes them back, so no response is
 * ever logged verbatim: recognised credential fields become fingerprints while
 * error, error_description and error_hint -- the parts worth reading -- survive
 * untouched.
 */
function describeResponse(raw: string): string {
	if (!raw) return '(empty body)';
	try {
		const parsed: unknown = JSON.parse(raw);
		if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
			const safe: Record<string, unknown> = {};
			for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
				safe[key] = SECRET_PARAMS.has(key) && typeof value === 'string'
					? `<${fingerprint(value)}>`
					: value;
			}
			return JSON.stringify(safe);
		}
	} catch {
		// Not JSON -- fall through to the masked preview below.
	}
	return `(unparseable body, ${raw.length} bytes) ${maskSecretish(raw.slice(0, 200))}`;
}

/**
 * With WHOOP_DEBUG_RAW=1, dump the first workout record this process sees,
 * verbatim, so the API's real field names can be read off the log. Off by
 * default: the payload is personal health data and belongs in a log only when
 * you are deliberately inspecting the response shape.
 */
function maybeLogRawWorkout(record: unknown): void {
	if (rawWorkoutLogged || process.env.WHOOP_DEBUG_RAW !== '1' || !record) return;
	rawWorkoutLogged = true;
	console.error('[whoop] raw workout record from /v2/activity/workout:');
	console.error(JSON.stringify(record, null, 2));
}

interface WhoopClientConfig {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	onTokenRefresh?: (tokens: WhoopTokens) => void;
	/** Reads the persisted pair, so a refresh always uses the newest known token. */
	loadPersistedTokens?: () => WhoopTokens | null;
}

interface PaginationParams {
	start?: string;
	end?: string;
	limit?: number;
	nextToken?: string;
}

export class WhoopClient {
	private tokens: WhoopTokens | null = null;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private readonly redirectUri: string;
	private readonly onTokenRefresh?: (tokens: WhoopTokens) => void;
	private readonly loadPersistedTokens?: () => WhoopTokens | null;

	constructor(config: WhoopClientConfig) {
		this.clientId = config.clientId;
		this.clientSecret = config.clientSecret;
		this.redirectUri = config.redirectUri;
		this.onTokenRefresh = config.onTokenRefresh;
		this.loadPersistedTokens = config.loadPersistedTokens;
	}

	/**
	 * Adopt a stored pair -- but never downgrade. Callers reload from the database
	 * on every tool call, and a snapshot taken before an in-flight refresh would
	 * otherwise overwrite the rotated token with the spent one that produced it.
	 */
	setTokens(tokens: WhoopTokens): void {
		if (this.tokens && tokens.expires_at < this.tokens.expires_at) {
			return;
		}
		this.tokens = tokens;
	}

	getAuthorizationUrl(scopes: string[]): string {
		const params = new URLSearchParams({
			client_id: this.clientId,
			redirect_uri: this.redirectUri,
			response_type: 'code',
			scope: scopes.join(' '),
			state: crypto.randomUUID(),
		});
		return `${WHOOP_AUTH_BASE}/auth?${params}`;
	}

	async exchangeCodeForTokens(code: string): Promise<WhoopTokens> {
		const response = await fetch(`${WHOOP_AUTH_BASE}/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: this.clientId,
				client_secret: this.clientSecret,
				redirect_uri: this.redirectUri,
			}),
		});

		if (!response.ok) {
			throw new Error(`Token exchange failed: HTTP ${response.status} ${describeResponse(await response.text())}`);
		}

		const data = await response.json() as { access_token: string; refresh_token: string; expires_in: number };
		const tokens: WhoopTokens = {
			access_token: data.access_token,
			refresh_token: data.refresh_token,
			expires_at: Date.now() + data.expires_in * 1000,
		};

		this.tokens = tokens;
		return tokens;
	}

	/**
	 * Whoop rotates the refresh token on every use: the value we send is spent
	 * the moment Whoop honours it. Two refreshes started from the same stored
	 * token therefore cannot both win -- the loser replays a consumed token and
	 * is rejected. Single-flight collapses concurrent callers onto one attempt
	 * so a replay is never issued in the first place.
	 *
	 * This is not hypothetical: syncDays fans out four getAll* calls through
	 * Promise.all, each of which enters request() and finds the same expiring
	 * token. Production logs showed ten separate bursts of exactly three
	 * simultaneous failures -- one winner, three losers -- every time.
	 */
	private refreshInFlight: Promise<void> | null = null;

	private isExpiring(tokens: WhoopTokens): boolean {
		return tokens.expires_at - Date.now() < REFRESH_SKEW_MS;
	}

	/** Refresh only if the current token is at or near expiry. */
	private async ensureFreshToken(): Promise<void> {
		if (this.tokens && !this.isExpiring(this.tokens)) return;
		await this.refreshTokens();
	}

	/** Public preflight: lets a caller rotate once before fanning out. */
	async ensureAuthenticated(): Promise<void> {
		if (!this.tokens) {
			throw new Error('Not authenticated');
		}
		await this.ensureFreshToken();
	}

	private refreshTokens(): Promise<void> {
		// Everyone who arrives while a refresh is running awaits that same
		// attempt and shares its outcome -- success or failure.
		if (this.refreshInFlight) {
			console.error('[whoop] refresh already in flight; joining it instead of issuing a second request');
			return this.refreshInFlight;
		}

		const attempt = this.performRefresh().finally(() => {
			this.refreshInFlight = null;
		});
		this.refreshInFlight = attempt;
		return attempt;
	}

	private async performRefresh(): Promise<void> {
		// The persisted pair is the authority. Another code path -- or a previous
		// run of this process -- may have rotated the token since our in-memory
		// snapshot was taken, and refreshing with the stale one would replay a
		// token that is already spent.
		const persisted = this.loadPersistedTokens?.() ?? null;
		if (persisted && (!this.tokens || persisted.expires_at > this.tokens.expires_at)) {
			console.error('[whoop] adopting a newer persisted token before refreshing');
			this.tokens = persisted;
		}

		// A refresh that completed while we were queued already gave us a usable
		// token; spending another one would be pure waste.
		if (this.tokens && !this.isExpiring(this.tokens)) {
			return;
		}

		const previousRefreshToken = this.tokens?.refresh_token;
		if (!previousRefreshToken) {
			throw new Error('No refresh token available');
		}

		// Whoop requires scope=offline on refresh requests. Omitting it gets an
		// invalid_request whose error_hint talks about redirect_uri whitelisting,
		// which sends you looking in the wrong place entirely. Note that a spent
		// refresh token produces that identical hint, so the hint alone can never
		// tell the two apart -- which is why the body is logged below.
		const body = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: previousRefreshToken,
			client_id: this.clientId,
			client_secret: this.clientSecret,
			scope: 'offline',
		});

		const attemptId = ++refreshAttemptCounter;
		console.error(
			`[whoop] refresh #${attemptId} POST ${WHOOP_AUTH_BASE}/token\n` +
			`[whoop] refresh #${attemptId} body: ${describeBody(body)}`
		);

		const startedAt = Date.now();
		const response = await fetch(`${WHOOP_AUTH_BASE}/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body,
		});

		const raw = await response.text();
		const elapsed = Date.now() - startedAt;

		if (!response.ok) {
			console.error(
				`[whoop] refresh #${attemptId} failed: HTTP ${response.status} ${response.statusText} after ${elapsed}ms\n` +
				`[whoop] refresh #${attemptId} sent refresh_token ${fingerprint(previousRefreshToken)}\n` +
				`[whoop] refresh #${attemptId} whoop response: ${describeResponse(raw)}`
			);
			// Leave this.tokens and the stored pair untouched. If Whoop rotated
			// server-side and still failed us, the stored token is already dead and
			// overwriting it with anything would only destroy evidence.
			throw new Error(`Token refresh failed: HTTP ${response.status} ${describeResponse(raw)}`);
		}

		let data: { access_token?: string; refresh_token?: string; expires_in?: number };
		try {
			data = JSON.parse(raw) as typeof data;
		} catch {
			console.error(`[whoop] refresh #${attemptId} returned a non-JSON body: ${describeResponse(raw)}`);
			throw new Error('Token refresh failed: response was not JSON');
		}

		if (!data.access_token) {
			console.error(`[whoop] refresh #${attemptId} response carried no access_token: ${describeResponse(raw)}`);
			throw new Error('Token refresh failed: no access_token in response');
		}

		if (!data.refresh_token) {
			console.error(`[whoop] refresh #${attemptId} response omitted refresh_token; retaining the previous one`);
		}

		// Whoop rotates refresh tokens: replaying a spent one fails, so the new
		// value has to replace the old. Falling back to the previous token only
		// when the field is genuinely absent keeps us from persisting undefined
		// over a working token.
		const rotated: WhoopTokens = {
			access_token: data.access_token,
			refresh_token: data.refresh_token ?? previousRefreshToken,
			expires_at: Date.now() + (data.expires_in ?? 3600) * 1000,
		};

		// Persist BEFORE adopting in memory. If the write throws, we keep using the
		// old token rather than holding a rotated value that no restart can recover.
		this.onTokenRefresh?.(rotated);
		this.tokens = rotated;

		console.error(
			`[whoop] refresh #${attemptId} ok in ${elapsed}ms: ` +
			`refresh_token ${fingerprint(previousRefreshToken)} -> ${fingerprint(rotated.refresh_token)}, ` +
			`expires ${new Date(rotated.expires_at).toISOString()}`
		);
	}

	private async request<T>(path: string, params?: Record<string, string>): Promise<T> {
		if (!this.tokens) {
			throw new Error('Not authenticated');
		}

		await this.ensureFreshToken();

		const url = new URL(`${WHOOP_API_BASE}${path}`);
		if (params) {
			for (const [key, value] of Object.entries(params)) {
				url.searchParams.set(key, value);
			}
		}

		const response = await fetch(url.toString(), {
			headers: { Authorization: `Bearer ${this.tokens.access_token}` },
		});

		if (!response.ok) {
			throw new Error(`API request failed: ${response.status} ${await response.text()}`);
		}

		return response.json() as Promise<T>;
	}

	async getProfile(): Promise<WhoopUser> {
		return this.request<WhoopUser>('/v2/user/profile/basic');
	}

	async getBodyMeasurement(): Promise<WhoopBodyMeasurement> {
		return this.request<WhoopBodyMeasurement>('/v2/user/measurement/body');
	}

	async getCycles(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopCycle>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopCycle>>('/v2/cycle', queryParams);
	}

	async getRecoveries(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopRecovery>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopRecovery>>('/v2/recovery', queryParams);
	}

	async getSleeps(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopSleep>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopSleep>>('/v2/activity/sleep', queryParams);
	}

	async getWorkouts(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopWorkout>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		const response = await this.request<WhoopPaginatedResponse<WhoopWorkout>>('/v2/activity/workout', queryParams);
		maybeLogRawWorkout(response.records?.[0]);
		return response;
	}

	async getAllCycles(params?: { start?: string; end?: string }): Promise<WhoopCycle[]> {
		const results: WhoopCycle[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getCycles({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}

	async getAllRecoveries(params?: { start?: string; end?: string }): Promise<WhoopRecovery[]> {
		const results: WhoopRecovery[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getRecoveries({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}

	async getAllSleeps(params?: { start?: string; end?: string }): Promise<WhoopSleep[]> {
		const results: WhoopSleep[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getSleeps({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}

	async getAllWorkouts(params?: { start?: string; end?: string }): Promise<WhoopWorkout[]> {
		const results: WhoopWorkout[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getWorkouts({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}
}
