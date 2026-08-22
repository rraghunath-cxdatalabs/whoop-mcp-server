import crypto from 'node:crypto';
import type { Request } from 'express';

export const AUTH_CODE_TTL_MS = 60 * 1000;
export const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;

export function secureToken(bytes = 32): string {
	return crypto.randomBytes(bytes).toString('base64url');
}

export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
	const computed = crypto.createHash('sha256').update(codeVerifier).digest().toString('base64url');
	const a = Buffer.from(computed);
	const b = Buffer.from(codeChallenge);
	if (a.length !== b.length) return false;
	return crypto.timingSafeEqual(a, b);
}

export function baseUrl(req: Request): string {
	const configured = process.env.PUBLIC_URL;
	if (configured) return configured.replace(/\/$/, '');
	const proto = (req.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0]?.trim() ?? req.protocol;
	const host = (req.headers['x-forwarded-host'] as string | undefined)?.split(',')[0]?.trim() ?? req.get('host');
	return `${proto}://${host}`;
}
