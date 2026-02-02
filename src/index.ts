/**
 * Harper Rate Limiting Plugin
 *
 * Provides rate limiting for Harper applications using rate-limiter-flexible.
 *
 * Features:
 * - Class decorator (@withRateLimit) for automatic rate limiting
 * - Multiple rate limiting strategies (by IP, by user, by endpoint)
 * - Configurable limits and windows
 * - In-memory and custom store support
 *
 * Usage:
 *
 * 1. Configure in config.yaml:
 *    harper-rate-limit:
 *      package: 'harper-rate-limit'
 *      points: 100          # requests allowed
 *      duration: 60         # per 60 seconds
 *      blockDuration: 0     # block duration when limit exceeded (0 = until points restored)
 *      keyPrefix: 'rl'      # key prefix for store
 *
 * 2. Apply decorator to resources:
 *    import { withRateLimit } from 'harper-rate-limit';
 *
 *    @withRateLimit({ points: 10, duration: 60 })
 *    export class MyResource extends Resource {
 *      async get(target, request) {
 *        // Rate limit checked automatically
 *      }
 *    }
 */

import { RateLimiterMemory, RateLimiterRes, IRateLimiterOptions } from 'rate-limiter-flexible';

// Maximum key length to prevent memory issues from malicious input
const MAX_KEY_LENGTH = 256;

// Default rate limiter configuration
let defaultConfig: IRateLimiterOptions = {
	points: 100, // Number of requests
	duration: 60, // Per 60 seconds
	blockDuration: 0, // Block duration when limit exceeded
	keyPrefix: 'rl',
};

/**
 * Security configuration options
 */
export interface SecurityConfig {
	/**
	 * Trust proxy headers (X-Forwarded-For, X-Real-IP) for client identification.
	 * SECURITY: Only enable this if Harper is behind a trusted reverse proxy.
	 * When false (default), only request.ip and connection.remoteAddress are used.
	 */
	trustProxy?: boolean;
	/**
	 * Which IP to use from X-Forwarded-For header (when trustProxy is true).
	 * 0 = rightmost (closest proxy), 1 = second from right, etc.
	 * Use 0 when your proxy appends to the header. Use higher values if you have
	 * multiple trusted proxies and need to skip them.
	 * Default: 0
	 */
	trustedProxyDepth?: number;
}

// Security configuration (secure defaults)
const securityConfig: SecurityConfig = {
	trustProxy: false,
	trustedProxyDepth: 0,
};

// Store instance (lazily initialized)
let rateLimiter: RateLimiterMemory | null = null;

/**
 * Get or create the default rate limiter instance
 */
function getRateLimiter(): RateLimiterMemory {
	if (!rateLimiter) {
		rateLimiter = new RateLimiterMemory(defaultConfig);
	}
	return rateLimiter;
}

/**
 * Configuration options for the plugin
 */
export interface ConfigureOptions extends Partial<IRateLimiterOptions>, SecurityConfig {}

/**
 * Configure the rate limit plugin. Called by Harper when loading the plugin.
 */
export function configure(options: ConfigureOptions): void {
	// Extract security options
	const { trustProxy, trustedProxyDepth, ...rateLimiterOptions } = options;

	// Update security config
	if (trustProxy !== undefined) {
		securityConfig.trustProxy = trustProxy;
	}
	if (trustedProxyDepth !== undefined) {
		securityConfig.trustedProxyDepth = trustedProxyDepth;
	}

	// Update rate limiter config
	defaultConfig = { ...defaultConfig, ...rateLimiterOptions };

	// Reset limiter so it picks up new config on next use
	rateLimiter = null;
}

/**
 * Get current security configuration (for testing/debugging)
 */
export function getSecurityConfig(): Readonly<SecurityConfig> {
	return { ...securityConfig };
}

/**
 * Sanitize a key to prevent memory issues from malicious input
 */
function sanitizeKey(key: string): string {
	if (key.length > MAX_KEY_LENGTH) {
		return key.substring(0, MAX_KEY_LENGTH);
	}
	return key;
}

/**
 * Extract IP address from X-Forwarded-For header securely.
 * Uses trustedProxyDepth to select which IP from the chain to trust.
 * Depth 0 = rightmost (closest proxy), 1 = second from right, etc.
 */
function extractIpFromForwardedFor(header: string, depth: number): string | null {
	const ips = header.split(',').map((ip) => ip.trim());
	// Select from the right (rightmost is the one added by our trusted proxy)
	const index = ips.length - 1 - depth;
	if (index >= 0 && index < ips.length) {
		return ips[index] || null;
	}
	return null;
}

/**
 * Get client IP address from request with security considerations.
 * Only trusts proxy headers when trustProxy is explicitly enabled.
 */
function getClientIp(request: any): string {
	// Only trust proxy headers if explicitly configured
	if (securityConfig.trustProxy) {
		const forwardedFor = request.headers?.['x-forwarded-for'] as string | undefined;
		if (forwardedFor) {
			const ip = extractIpFromForwardedFor(forwardedFor, securityConfig.trustedProxyDepth ?? 0);
			if (ip) {
				return ip;
			}
		}

		const realIp = request.headers?.['x-real-ip'] as string | undefined;
		if (realIp) {
			return realIp;
		}
	}

	// Use direct connection info (cannot be spoofed)
	return request.ip || request.connection?.remoteAddress || 'unknown';
}

/**
 * Get client identifier from request (IP address or user ID)
 */
function getClientKey(request: any, options?: RateLimitOptions): string {
	// If keyGenerator is provided, use it (sanitize the result)
	if (options?.keyGenerator) {
		return sanitizeKey(options.keyGenerator(request));
	}

	// Try to use authenticated user ID first
	if (options?.byUser && request.session?.user) {
		const userId = String(request.session.user);
		return sanitizeKey(`user:${userId}`);
	}

	// Fall back to IP address
	const ip = getClientIp(request);
	return sanitizeKey(`ip:${ip}`);
}

/**
 * Check rate limit and throw error if exceeded
 */
export async function checkRateLimit(request: any, options?: RateLimitOptions): Promise<RateLimiterRes> {
	const key = getClientKey(request, options);

	// Use custom limiter if provided, otherwise use default
	const limiter = options?.limiter || getRateLimiter();

	try {
		const result = await limiter.consume(key, options?.pointsToConsume || 1);
		return result;
	} catch (rejRes) {
		// Rate limit exceeded
		const error = new Error('Too many requests. Please try again later.');
		(error as any).statusCode = 429;
		(error as any).retryAfter = Math.ceil((rejRes as RateLimiterRes).msBeforeNext / 1000);
		throw error;
	}
}

/**
 * Options for rate limiting
 */
export interface RateLimitOptions {
	/** Custom points for this endpoint */
	points?: number;
	/** Custom duration in seconds */
	duration?: number;
	/** Block duration when exceeded */
	blockDuration?: number;
	/** Points to consume per request (default 1) */
	pointsToConsume?: number;
	/** Use user ID instead of IP for key */
	byUser?: boolean;
	/** Custom key generator function */
	keyGenerator?: (_request: any) => string;
	/** Custom rate limiter instance */
	limiter?: RateLimiterMemory;
	/** Methods to rate limit (default: all) */
	methods?: ('get' | 'post' | 'put' | 'delete' | 'patch')[];
}

/**
 * Create a custom rate limiter with specific options
 */
export function createRateLimiter(options: Partial<IRateLimiterOptions>): RateLimiterMemory {
	return new RateLimiterMemory({ ...defaultConfig, ...options });
}

/**
 * Class decorator that adds rate limiting to Resource methods.
 *
 * @example
 * // Basic usage - uses default limits
 * @withRateLimit()
 * export class MyResource extends Resource { ... }
 *
 * // Custom limits
 * @withRateLimit({ points: 10, duration: 60 })
 * export class StrictResource extends Resource { ... }
 *
 * // Rate limit by user instead of IP
 * @withRateLimit({ byUser: true })
 * export class UserResource extends Resource { ... }
 *
 * // Only rate limit specific methods
 * @withRateLimit({ methods: ['post', 'put'] })
 * export class PartialResource extends Resource { ... }
 */
export function withRateLimit(options?: RateLimitOptions) {
	// Create limiter with custom options if provided
	let limiter: RateLimiterMemory | undefined;
	if (options?.points || options?.duration || options?.blockDuration) {
		limiter = createRateLimiter({
			points: options.points,
			duration: options.duration,
			blockDuration: options.blockDuration,
		});
	}

	const rateLimitOptions: RateLimitOptions = {
		...options,
		limiter: limiter || options?.limiter,
	};

	const methods = options?.methods || ['get', 'post', 'put', 'delete', 'patch'];

	return function <T extends new (..._args: any[]) => any>(BaseClass: T): T {
		return class extends BaseClass {
			async get(...args: any[]): Promise<any> {
				if (methods.includes('get')) {
					const [, request] = args;
					await checkRateLimit(request, rateLimitOptions);
				}
				if (super.get) {
					return super.get(...args);
				}
			}

			async post(...args: any[]): Promise<any> {
				if (methods.includes('post')) {
					const [, , request] = args;
					await checkRateLimit(request, rateLimitOptions);
				}
				if (super.post) {
					return super.post(...args);
				}
			}

			async put(...args: any[]): Promise<any> {
				if (methods.includes('put')) {
					const [, , request] = args;
					await checkRateLimit(request, rateLimitOptions);
				}
				if (super.put) {
					return super.put(...args);
				}
			}

			async delete(...args: any[]): Promise<any> {
				if (methods.includes('delete')) {
					const [, , request] = args;
					await checkRateLimit(request, rateLimitOptions);
				}
				if (super.delete) {
					return super.delete(...args);
				}
			}

			async patch(...args: any[]): Promise<any> {
				if (methods.includes('patch')) {
					const [, , request] = args;
					await checkRateLimit(request, rateLimitOptions);
				}
				if (super.patch) {
					return super.patch(...args);
				}
			}
		} as T;
	};
}

/**
 * Middleware-style rate limiting for manual use
 */
export async function rateLimit(request: any, options?: RateLimitOptions): Promise<void> {
	await checkRateLimit(request, options);
}

/**
 * Get remaining points for a key (useful for headers)
 */
export async function getRemainingPoints(
	request: any,
	options?: RateLimitOptions
): Promise<{ remaining: number; resetMs: number } | null> {
	const key = getClientKey(request, options);
	const limiter = options?.limiter || getRateLimiter();

	try {
		const result = await limiter.get(key);
		if (result) {
			return {
				remaining: result.remainingPoints,
				resetMs: result.msBeforeNext,
			};
		}
		return null;
	} catch {
		return null;
	}
}

/**
 * Reset rate limit for a specific key
 */
export async function resetRateLimit(request: any, options?: RateLimitOptions): Promise<void> {
	const key = getClientKey(request, options);
	const limiter = options?.limiter || getRateLimiter();
	await limiter.delete(key);
}

// Re-export types for convenience
export type { RateLimiterRes, IRateLimiterOptions };
