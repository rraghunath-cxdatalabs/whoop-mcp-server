import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import express, { type Request, type Response, type NextFunction } from 'express';
import { WhoopClient } from './whoop-client.js';
import { WhoopDatabase } from './database.js';
import { WhoopSync } from './sync.js';
import { secureToken, verifyPkceS256, baseUrl, AUTH_CODE_TTL_MS, ACCESS_TOKEN_TTL_MS } from './oauth.js';

interface ToolArguments {
	days?: number;
	full?: boolean;
}

const config = {
	clientId: process.env.WHOOP_CLIENT_ID ?? '',
	clientSecret: process.env.WHOOP_CLIENT_SECRET ?? '',
	redirectUri: process.env.WHOOP_REDIRECT_URI ?? 'http://localhost:3000/callback',
	dbPath: process.env.DB_PATH ?? './whoop.db',
	port: Number.parseInt(process.env.PORT ?? '3000', 10),
	mode: process.env.MCP_MODE ?? 'http',
};

const db = new WhoopDatabase(config.dbPath);
const client = new WhoopClient({
	clientId: config.clientId,
	clientSecret: config.clientSecret,
	redirectUri: config.redirectUri,
	onTokenRefresh: tokens => db.saveTokens(tokens),
});

const existingTokens = db.getTokens();
if (existingTokens) {
	client.setTokens(existingTokens);
}

const sync = new WhoopSync(client, db);

const SESSION_TTL_MS = 30 * 60 * 1000;
const transports = new Map<string, { transport: StreamableHTTPServerTransport; lastAccess: number }>();

function cleanupStaleSessions(): void {
	const now = Date.now();
	for (const [sessionId, session] of transports) {
		if (now - session.lastAccess > SESSION_TTL_MS) {
			session.transport.close().catch(() => {});
			transports.delete(sessionId);
		}
	}
}

setInterval(cleanupStaleSessions, 5 * 60 * 1000);

function formatDuration(millis: number | null): string {
	if (!millis) return 'N/A';
	const hours = Math.floor(millis / 3_600_000);
	const minutes = Math.floor((millis % 3_600_000) / 60_000);
	return `${hours}h ${minutes}m`;
}

function formatDate(isoString: string): string {
	return new Date(isoString).toLocaleDateString('en-US', {
		weekday: 'short',
		month: 'short',
		day: 'numeric',
	});
}

function getRecoveryZone(score: number): string {
	if (score >= 67) return 'Green (Well Recovered)';
	if (score >= 34) return 'Yellow (Moderate)';
	return 'Red (Needs Rest)';
}

function getStrainZone(strain: number): string {
	if (strain >= 18) return 'All Out (18-21)';
	if (strain >= 14) return 'High (14-17)';
	if (strain >= 10) return 'Moderate (10-13)';
	return 'Light (0-9)';
}

function validateDays(value: unknown): number {
	if (value === undefined || value === null) return 14;
	const num = typeof value === 'number' ? value : Number.parseInt(String(value), 10);
	if (Number.isNaN(num) || num < 1) return 14;
	return Math.min(num, 90);
}

function validateBoolean(value: unknown): boolean {
	if (typeof value === 'boolean') return value;
	if (value === 'true') return true;
	return false;
}

function createMcpServer(): Server {
	const server = new Server(
		{ name: 'whoop-mcp-server', version: '1.0.0' },
		{ capabilities: { tools: {} } }
	);

	server.setRequestHandler(ListToolsRequestSchema, async () => ({
		tools: [
			{
				name: 'get_today',
				description: "Get today's Whoop data including recovery score, last night's sleep, and current strain.",
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
			{
				name: 'get_recovery_trends',
				description: 'Get recovery score trends over time, including HRV and resting heart rate patterns.',
				inputSchema: {
					type: 'object',
					properties: { days: { type: 'number', description: 'Number of days to analyze (default: 14, max: 90)' } },
					required: [],
				},
			},
			{
				name: 'get_sleep_analysis',
				description: 'Get detailed sleep analysis including duration, stages, efficiency, and sleep debt.',
				inputSchema: {
					type: 'object',
					properties: { days: { type: 'number', description: 'Number of days to analyze (default: 14, max: 90)' } },
					required: [],
				},
			},
			{
				name: 'get_strain_history',
				description: 'Get training strain history and workout data.',
				inputSchema: {
					type: 'object',
					properties: { days: { type: 'number', description: 'Number of days to analyze (default: 14, max: 90)' } },
					required: [],
				},
			},
			{
				name: 'sync_data',
				description: 'Manually trigger a data sync from Whoop.',
				inputSchema: {
					type: 'object',
					properties: { full: { type: 'boolean', description: 'Force a full 90-day sync (default: false)' } },
					required: [],
				},
			},
			{
				name: 'get_auth_url',
				description: 'Get the Whoop authorization URL to connect your account.',
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
		],
	}));

	server.setRequestHandler(CallToolRequestSchema, async request => {
		const { name, arguments: args } = request.params;
		const typedArgs = (args ?? {}) as ToolArguments;

		try {
			const dataTools = ['get_today', 'get_recovery_trends', 'get_sleep_analysis', 'get_strain_history'];
			if (dataTools.includes(name)) {
				const tokens = db.getTokens();
				if (!tokens) {
					return { content: [{ type: 'text', text: 'Not authenticated with Whoop. Use get_auth_url to authorize first.' }] };
				}
				client.setTokens(tokens);
				try {
					await sync.smartSync();
				} catch {
					// Continue with cached data
				}
			}

			switch (name) {
				case 'get_today': {
					const recovery = db.getLatestRecovery();
					const sleep = db.getLatestSleep();
					const cycle = db.getLatestCycle();

					if (!recovery && !sleep && !cycle) {
						return { content: [{ type: 'text', text: 'No data available. Try running sync_data first.' }] };
					}

					let response = "# Today's Whoop Summary\n\n";

					if (recovery) {
						response += `## Recovery: ${recovery.recovery_score ?? 'N/A'}% ${recovery.recovery_score ? getRecoveryZone(recovery.recovery_score) : ''}\n`;
						response += `- **HRV**: ${recovery.hrv_rmssd?.toFixed(1) ?? 'N/A'} ms\n`;
						response += `- **Resting HR**: ${recovery.resting_hr ?? 'N/A'} bpm\n`;
						if (recovery.spo2) response += `- **SpO2**: ${recovery.spo2.toFixed(1)}%\n`;
						if (recovery.skin_temp) response += `- **Skin Temp**: ${recovery.skin_temp.toFixed(1)}°C\n`;
						response += '\n';
					}

					if (sleep) {
						const totalSleep = (sleep.total_in_bed_milli ?? 0) - (sleep.total_awake_milli ?? 0);
						response += `## Last Night's Sleep\n`;
						response += `- **Total Sleep**: ${formatDuration(totalSleep)}\n`;
						response += `- **Performance**: ${sleep.sleep_performance?.toFixed(0) ?? 'N/A'}%\n`;
						response += `- **Efficiency**: ${sleep.sleep_efficiency?.toFixed(0) ?? 'N/A'}%\n`;
						response += `- **Stages**: Light ${formatDuration(sleep.total_light_milli)}, Deep ${formatDuration(sleep.total_deep_milli)}, REM ${formatDuration(sleep.total_rem_milli)}\n`;
						if (sleep.respiratory_rate) response += `- **Respiratory Rate**: ${sleep.respiratory_rate.toFixed(1)} breaths/min\n`;
						response += '\n';
					}

					if (cycle) {
						response += `## Current Strain\n`;
						response += `- **Day Strain**: ${cycle.strain?.toFixed(1) ?? 'N/A'} ${cycle.strain ? getStrainZone(cycle.strain) : ''}\n`;
						if (cycle.kilojoule) response += `- **Calories**: ${Math.round(cycle.kilojoule / 4.184)} kcal\n`;
						if (cycle.avg_hr) response += `- **Avg HR**: ${cycle.avg_hr} bpm\n`;
						if (cycle.max_hr) response += `- **Max HR**: ${cycle.max_hr} bpm\n`;
					}

					return { content: [{ type: 'text', text: response }] };
				}

				case 'get_recovery_trends': {
					const days = validateDays(typedArgs.days);
					const trends = db.getRecoveryTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No recovery data available for the requested period.' }] };
					}

					let response = `# Recovery Trends (Last ${days} Days)\n\n`;
					response += '| Date | Recovery | HRV | RHR |\n|------|----------|-----|-----|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.recovery_score}% | ${day.hrv?.toFixed(1) ?? 'N/A'} ms | ${day.rhr ?? 'N/A'} bpm |\n`;
					}

					const avgRecovery = trends.reduce((sum, d) => sum + (d.recovery_score || 0), 0) / trends.length;
					const avgHrv = trends.reduce((sum, d) => sum + (d.hrv || 0), 0) / trends.length;
					const avgRhr = trends.reduce((sum, d) => sum + (d.rhr || 0), 0) / trends.length;

					response += `\n## Averages\n- **Recovery**: ${avgRecovery.toFixed(0)}%\n- **HRV**: ${avgHrv.toFixed(1)} ms\n- **RHR**: ${avgRhr.toFixed(0)} bpm\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'get_sleep_analysis': {
					const days = validateDays(typedArgs.days);
					const trends = db.getSleepTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No sleep data available for the requested period.' }] };
					}

					let response = `# Sleep Analysis (Last ${days} Days)\n\n`;
					response += '| Date | Duration | Performance | Efficiency |\n|------|----------|-------------|------------|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.total_sleep_hours?.toFixed(1) ?? 'N/A'}h | ${day.performance?.toFixed(0) ?? 'N/A'}% | ${day.efficiency?.toFixed(0) ?? 'N/A'}% |\n`;
					}

					const avgDuration = trends.reduce((sum, d) => sum + (d.total_sleep_hours || 0), 0) / trends.length;
					const avgPerf = trends.reduce((sum, d) => sum + (d.performance || 0), 0) / trends.length;
					const avgEff = trends.reduce((sum, d) => sum + (d.efficiency || 0), 0) / trends.length;

					response += `\n## Averages\n- **Duration**: ${avgDuration.toFixed(1)} hours\n- **Performance**: ${avgPerf.toFixed(0)}%\n- **Efficiency**: ${avgEff.toFixed(0)}%\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'get_strain_history': {
					const days = validateDays(typedArgs.days);
					const trends = db.getStrainTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No strain data available for the requested period.' }] };
					}

					let response = `# Strain History (Last ${days} Days)\n\n`;
					response += '| Date | Strain | Calories |\n|------|--------|----------|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.strain?.toFixed(1) ?? 'N/A'} | ${day.calories ?? 'N/A'} kcal |\n`;
					}

					const avgStrain = trends.reduce((sum, d) => sum + (d.strain || 0), 0) / trends.length;
					const avgCalories = trends.reduce((sum, d) => sum + (d.calories || 0), 0) / trends.length;

					response += `\n## Averages\n- **Daily Strain**: ${avgStrain.toFixed(1)}\n- **Daily Calories**: ${Math.round(avgCalories)} kcal\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'sync_data': {
					const tokens = db.getTokens();
					if (!tokens) {
						return { content: [{ type: 'text', text: 'Not authenticated with Whoop. Use get_auth_url to authorize first.' }] };
					}
					client.setTokens(tokens);

					const full = validateBoolean(typedArgs.full);
					let stats;

					if (full) {
						stats = await sync.syncDays(90);
					} else {
						const result = await sync.smartSync();
						if (result.type === 'skip') {
							return { content: [{ type: 'text', text: 'Data is already up to date (synced within the last hour).' }] };
						}
						stats = result.stats;
					}

					return {
						content: [{
							type: 'text',
							text: `Sync complete!\n- Cycles: ${stats?.cycles}\n- Recoveries: ${stats?.recoveries}\n- Sleeps: ${stats?.sleeps}\n- Workouts: ${stats?.workouts}`,
						}],
					};
				}

				case 'get_auth_url': {
					const scopes = ['read:profile', 'read:body_measurement', 'read:cycles', 'read:recovery', 'read:sleep', 'read:workout', 'offline'];
					const url = client.getAuthorizationUrl(scopes);
					return {
						content: [{
							type: 'text',
							text: `To authorize with Whoop:\n\n1. Visit: ${url}\n2. Log in and authorize\n3. You'll be redirected back automatically\n\nRedirect URI: ${config.redirectUri}`,
						}],
					};
				}

				default:
					throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : 'Unknown error';
			return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
		}
	});

	return server;
}

async function main(): Promise<void> {
	if (config.mode === 'stdio') {
		const server = createMcpServer();
		const transport = new StdioServerTransport();
		await server.connect(transport);
		process.stderr.write('Whoop MCP server running on stdio\n');
	} else {
		const app = express();
		app.set('trust proxy', true);
		app.use(express.json());
		app.use(express.urlencoded({ extended: true }));

		app.get('/.well-known/oauth-authorization-server', (req: Request, res: Response) => {
			const base = baseUrl(req);
			res.json({
				issuer: base,
				authorization_endpoint: `${base}/oauth/authorize`,
				token_endpoint: `${base}/oauth/token`,
				registration_endpoint: `${base}/register`,
				response_types_supported: ['code'],
				grant_types_supported: ['authorization_code', 'refresh_token'],
				code_challenge_methods_supported: ['S256'],
				token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
				scopes_supported: ['mcp'],
			});
		});

		app.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
			const base = baseUrl(req);
			res.json({
				resource: `${base}/mcp`,
				authorization_servers: [base],
			});
		});

		app.post('/register', (req: Request, res: Response) => {
			const body = req.body as { redirect_uris?: unknown; client_name?: unknown; token_endpoint_auth_method?: unknown } | undefined;
			const redirectUris = body?.redirect_uris;
			if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every(u => typeof u === 'string')) {
				res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be a non-empty string array' });
				return;
			}
			const authMethod = typeof body?.token_endpoint_auth_method === 'string' ? body.token_endpoint_auth_method : 'none';
			const clientId = secureToken(16);
			const clientSecret = authMethod === 'none' ? null : secureToken(32);
			const clientName = typeof body?.client_name === 'string' ? body.client_name : null;

			db.createOAuthClient({
				client_id: clientId,
				client_secret: clientSecret,
				client_name: clientName,
				redirect_uris: redirectUris as string[],
			});

			res.status(201).json({
				client_id: clientId,
				...(clientSecret ? { client_secret: clientSecret } : {}),
				client_id_issued_at: Math.floor(Date.now() / 1000),
				client_secret_expires_at: 0,
				redirect_uris: redirectUris,
				token_endpoint_auth_method: authMethod,
				grant_types: ['authorization_code', 'refresh_token'],
				response_types: ['code'],
				...(clientName ? { client_name: clientName } : {}),
			});
		});

		app.get('/oauth/authorize', (req: Request, res: Response) => {
			const clientId = req.query.client_id as string | undefined;
			const redirectUri = req.query.redirect_uri as string | undefined;
			const responseType = req.query.response_type as string | undefined;
			const codeChallenge = req.query.code_challenge as string | undefined;
			const codeChallengeMethod = req.query.code_challenge_method as string | undefined;
			const state = req.query.state as string | undefined;
			const scope = req.query.scope as string | undefined;

			if (!clientId) { res.status(400).send('Missing client_id'); return; }
			const oauthClient = db.getOAuthClient(clientId);
			if (!oauthClient) { res.status(400).send('Unknown client_id'); return; }
			if (!redirectUri || !oauthClient.redirect_uris.includes(redirectUri)) {
				res.status(400).send('Invalid redirect_uri');
				return;
			}

			const redirect = new URL(redirectUri);
			const fail = (err: string, desc?: string): void => {
				redirect.searchParams.set('error', err);
				if (desc) redirect.searchParams.set('error_description', desc);
				if (state) redirect.searchParams.set('state', state);
				res.redirect(302, redirect.toString());
			};

			if (responseType !== 'code') { fail('unsupported_response_type'); return; }
			if (!codeChallenge || codeChallengeMethod !== 'S256') {
				fail('invalid_request', 'PKCE S256 code_challenge is required');
				return;
			}

			const code = secureToken(32);
			db.createOAuthCode({
				code,
				client_id: clientId,
				redirect_uri: redirectUri,
				code_challenge: codeChallenge,
				code_challenge_method: 'S256',
				scope: scope ?? null,
				expires_at: Date.now() + AUTH_CODE_TTL_MS,
			});

			redirect.searchParams.set('code', code);
			if (state) redirect.searchParams.set('state', state);
			res.redirect(302, redirect.toString());
		});

		app.post('/oauth/token', (req: Request, res: Response) => {
			const body = req.body as Record<string, string | undefined> | undefined;
			const grantType = body?.grant_type;

			if (grantType === 'authorization_code') {
				const code = body?.code;
				const redirectUri = body?.redirect_uri;
				const clientId = body?.client_id;
				const codeVerifier = body?.code_verifier;

				if (!code || !redirectUri || !clientId || !codeVerifier) {
					res.status(400).json({ error: 'invalid_request' });
					return;
				}
				const oauthClient = db.getOAuthClient(clientId);
				if (!oauthClient) { res.status(401).json({ error: 'invalid_client' }); return; }

				const authCode = db.consumeOAuthCode(code);
				if (!authCode || authCode.client_id !== clientId || authCode.redirect_uri !== redirectUri) {
					res.status(400).json({ error: 'invalid_grant' });
					return;
				}
				if (!verifyPkceS256(codeVerifier, authCode.code_challenge)) {
					res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
					return;
				}

				const accessToken = secureToken(32);
				const refreshToken = secureToken(32);
				db.createOAuthToken({
					access_token: accessToken,
					refresh_token: refreshToken,
					client_id: clientId,
					expires_at: Date.now() + ACCESS_TOKEN_TTL_MS,
					scope: authCode.scope,
				});

				res.json({
					access_token: accessToken,
					token_type: 'Bearer',
					expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
					refresh_token: refreshToken,
					...(authCode.scope ? { scope: authCode.scope } : {}),
				});
				return;
			}

			if (grantType === 'refresh_token') {
				const refreshToken = body?.refresh_token;
				const clientId = body?.client_id;
				if (!refreshToken || !clientId) { res.status(400).json({ error: 'invalid_request' }); return; }
				const oauthClient = db.getOAuthClient(clientId);
				if (!oauthClient) { res.status(401).json({ error: 'invalid_client' }); return; }

				const existing = db.consumeRefreshToken(refreshToken);
				if (!existing || existing.client_id !== clientId) {
					res.status(400).json({ error: 'invalid_grant' });
					return;
				}

				const accessToken = secureToken(32);
				const newRefresh = secureToken(32);
				db.createOAuthToken({
					access_token: accessToken,
					refresh_token: newRefresh,
					client_id: clientId,
					expires_at: Date.now() + ACCESS_TOKEN_TTL_MS,
					scope: existing.scope,
				});

				res.json({
					access_token: accessToken,
					token_type: 'Bearer',
					expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
					refresh_token: newRefresh,
					...(existing.scope ? { scope: existing.scope } : {}),
				});
				return;
			}

			res.status(400).json({ error: 'unsupported_grant_type' });
		});

		function requireBearer(req: Request, res: Response, next: NextFunction): void {
			const wwwAuth = `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`;
			const header = req.headers.authorization;
			const match = header?.match(/^Bearer\s+(.+)$/i);
			const token = match?.[1];
			if (!token) {
				res.setHeader('WWW-Authenticate', wwwAuth);
				res.status(401).json({ error: 'invalid_token', error_description: 'Missing bearer token' });
				return;
			}
			const record = db.getOAuthAccessToken(token);
			if (!record) {
				res.setHeader('WWW-Authenticate', `${wwwAuth}, error="invalid_token"`);
				res.status(401).json({ error: 'invalid_token', error_description: 'Invalid or expired token' });
				return;
			}
			next();
		}

		const authScopes = ['read:profile', 'read:body_measurement', 'read:cycles', 'read:recovery', 'read:sleep', 'read:workout', 'offline'];

		app.get('/auth', (_req: Request, res: Response) => {
			res.redirect(302, client.getAuthorizationUrl(authScopes));
		});

		app.get('/callback', async (req: Request, res: Response) => {
			const code = req.query.code as string | undefined;
			if (!code) {
				res.status(400).send('Missing authorization code');
				return;
			}

			try {
				const tokens = await client.exchangeCodeForTokens(code);
				db.saveTokens(tokens);
				sync.syncDays(90).catch(() => {});
				res.send('Authorization successful! You can close this window.');
			} catch {
				res.status(500).send('Authorization failed. Please try again.');
			}
		});

		app.get('/health', (_req: Request, res: Response) => {
			res.json({ status: 'ok', authenticated: Boolean(db.getTokens()) });
		});

		app.all('/mcp', requireBearer, async (req: Request, res: Response) => {
			const sessionId = req.headers['mcp-session-id'] as string | undefined;

			if (req.method === 'DELETE' && sessionId && transports.has(sessionId)) {
				const session = transports.get(sessionId)!;
				await session.transport.close();
				transports.delete(sessionId);
				res.status(200).send('Session closed');
				return;
			}

			if (req.method === 'POST') {
				let transport: StreamableHTTPServerTransport;

				if (sessionId && transports.has(sessionId)) {
					const session = transports.get(sessionId)!;
					session.lastAccess = Date.now();
					transport = session.transport;
				} else {
					transport = new StreamableHTTPServerTransport({
						sessionIdGenerator: () => crypto.randomUUID(),
						onsessioninitialized: newSessionId => {
							transports.set(newSessionId, { transport, lastAccess: Date.now() });
						},
					});

					const server = createMcpServer();
					await server.connect(transport);
				}

				await transport.handleRequest(req, res);
				return;
			}

			res.status(405).send('Method not allowed');
		});

		app.get('/sse', (_req: Request, res: Response) => {
			res.status(410).send('SSE endpoint deprecated. Use /mcp with Streamable HTTP transport.');
		});

		const server = app.listen(config.port, '0.0.0.0', () => {
			process.stdout.write(`Whoop MCP server running on http://0.0.0.0:${config.port}\n`);
		});

		const shutdown = (): void => {
			process.stdout.write('\nShutting down...\n');
			for (const [, session] of transports) {
				session.transport.close().catch(() => {});
			}
			transports.clear();
			db.close();
			server.close(() => process.exit(0));
		};

		process.on('SIGTERM', shutdown);
		process.on('SIGINT', shutdown);
	}
}

main().catch(error => {
	process.stderr.write(`Fatal error: ${error}\n`);
	process.exit(1);
});
