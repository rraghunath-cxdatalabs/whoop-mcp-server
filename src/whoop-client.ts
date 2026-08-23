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

let rawWorkoutLogged = false;

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

	constructor(config: WhoopClientConfig) {
		this.clientId = config.clientId;
		this.clientSecret = config.clientSecret;
		this.redirectUri = config.redirectUri;
		this.onTokenRefresh = config.onTokenRefresh;
	}

	setTokens(tokens: WhoopTokens): void {
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
			throw new Error(`Token exchange failed: ${await response.text()}`);
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

	private async refreshTokens(): Promise<void> {
		const previousRefreshToken = this.tokens?.refresh_token;
		if (!previousRefreshToken) {
			throw new Error('No refresh token available');
		}

		// Whoop requires scope=offline on refresh requests. Omitting it gets an
		// invalid_request whose error_hint talks about redirect_uri whitelisting,
		// which sends you looking in the wrong place entirely.
		const body = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: previousRefreshToken,
			client_id: this.clientId,
			client_secret: this.clientSecret,
			scope: 'offline',
		});

		const response = await fetch(`${WHOOP_AUTH_BASE}/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body,
		});

		const raw = await response.text();

		if (!response.ok) {
			console.error(
				`[whoop] token refresh failed: HTTP ${response.status} ${response.statusText}\n` +
				`[whoop] request scopes: offline; client_id ends ...${this.clientId.slice(-4)}\n` +
				`[whoop] whoop response: ${raw || '(empty body)'}`
			);
			throw new Error(`Token refresh failed: HTTP ${response.status} ${raw || '(empty body)'}`);
		}

		let data: { access_token?: string; refresh_token?: string; expires_in?: number };
		try {
			data = JSON.parse(raw) as typeof data;
		} catch {
			console.error(`[whoop] token refresh returned a non-JSON body: ${raw || '(empty body)'}`);
			throw new Error('Token refresh failed: response was not JSON');
		}

		if (!data.access_token) {
			console.error(`[whoop] token refresh response carried no access_token: ${raw}`);
			throw new Error('Token refresh failed: no access_token in response');
		}

		if (!data.refresh_token) {
			console.error('[whoop] refresh response omitted refresh_token; retaining the previous one');
		}

		// Whoop rotates refresh tokens: replaying a spent one fails, so the new
		// value has to replace the old. Falling back to the previous token only
		// when the field is genuinely absent keeps us from persisting undefined
		// over a working token.
		this.tokens = {
			access_token: data.access_token,
			refresh_token: data.refresh_token ?? previousRefreshToken,
			expires_at: Date.now() + (data.expires_in ?? 3600) * 1000,
		};

		// Persist before returning: the rotated token is the only one Whoop will
		// accept from here on, and losing it means re-authorizing by hand.
		this.onTokenRefresh?.(this.tokens);
	}

	private async request<T>(path: string, params?: Record<string, string>): Promise<T> {
		if (!this.tokens) {
			throw new Error('Not authenticated');
		}

		if (this.tokens.expires_at - Date.now() < 5 * 60 * 1000) {
			await this.refreshTokens();
		}

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
