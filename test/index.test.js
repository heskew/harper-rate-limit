import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
	configure,
	checkRateLimit,
	rateLimit,
	createRateLimiter,
	withRateLimit,
	getRemainingPoints,
	resetRateLimit,
	getSecurityConfig,
} from '../dist/index.js';

describe('Rate Limiting', () => {
	beforeEach(() => {
		// Reset to high limits and secure defaults for tests
		configure({
			points: 1000,
			duration: 60,
			blockDuration: 0,
			keyPrefix: 'test',
			trustProxy: false,
			trustedProxyDepth: 0,
		});
	});

	describe('configure', () => {
		it('should update default configuration', () => {
			configure({ points: 50, duration: 30 });
			// Config is applied to new limiters
			const limiter = createRateLimiter({});
			assert.ok(limiter);
		});
	});

	describe('checkRateLimit', () => {
		it('should allow requests within limit', async () => {
			const request = {
				headers: {},
				ip: '127.0.0.1',
			};

			const result = await checkRateLimit(request);
			assert.ok(result);
			assert.ok(result.remainingPoints >= 0);
		});

		it('should ignore x-forwarded-for header when trustProxy is false', async () => {
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			// Two requests with different X-Forwarded-For but same real IP
			const request1 = {
				headers: { 'x-forwarded-for': '1.2.3.4' },
				ip: '192.168.50.1',
			};
			const request2 = {
				headers: { 'x-forwarded-for': '5.6.7.8' },
				ip: '192.168.50.1',
			};

			// First request succeeds
			await checkRateLimit(request1, { limiter });

			// Second request should fail (same IP, header ignored)
			try {
				await checkRateLimit(request2, { limiter });
				assert.fail('Should have thrown - headers should be ignored');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}
		});

		it('should use x-forwarded-for header when trustProxy is true', async () => {
			configure({ points: 1000, duration: 60, trustProxy: true });
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			// Two requests with different X-Forwarded-For
			const request1 = {
				headers: { 'x-forwarded-for': '1.2.3.4' },
				ip: '192.168.50.2',
			};
			const request2 = {
				headers: { 'x-forwarded-for': '5.6.7.8' },
				ip: '192.168.50.2',
			};

			// Both should succeed (different forwarded IPs)
			await checkRateLimit(request1, { limiter });
			await checkRateLimit(request2, { limiter });
		});

		it('should ignore x-real-ip header when trustProxy is false', async () => {
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			const request1 = {
				headers: { 'x-real-ip': '10.0.0.1' },
				ip: '192.168.50.3',
			};
			const request2 = {
				headers: { 'x-real-ip': '10.0.0.2' },
				ip: '192.168.50.3',
			};

			await checkRateLimit(request1, { limiter });

			try {
				await checkRateLimit(request2, { limiter });
				assert.fail('Should have thrown - headers should be ignored');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}
		});

		it('should use x-real-ip header when trustProxy is true', async () => {
			configure({ points: 1000, duration: 60, trustProxy: true });
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			const request1 = {
				headers: { 'x-real-ip': '10.0.0.1' },
				ip: '192.168.50.4',
			};
			const request2 = {
				headers: { 'x-real-ip': '10.0.0.2' },
				ip: '192.168.50.4',
			};

			// Both should succeed (different real IPs)
			await checkRateLimit(request1, { limiter });
			await checkRateLimit(request2, { limiter });
		});

		it('should use user ID when byUser option is set', async () => {
			const request = {
				headers: {},
				session: { user: 'user123' },
			};

			const result = await checkRateLimit(request, { byUser: true });
			assert.ok(result);
		});

		it('should use custom keyGenerator', async () => {
			const request = {
				headers: { 'x-api-key': 'my-api-key' },
			};

			const result = await checkRateLimit(request, {
				keyGenerator: (req) => `api:${req.headers['x-api-key']}`,
			});
			assert.ok(result);
		});

		it('should throw 429 when limit exceeded', async () => {
			const limiter = createRateLimiter({ points: 1, duration: 60 });
			const request = { headers: {}, ip: '192.168.1.100' };

			// First request should succeed
			await checkRateLimit(request, { limiter });

			// Second request should fail
			try {
				await checkRateLimit(request, { limiter });
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.statusCode, 429);
				assert.equal(error.message, 'Too many requests. Please try again later.');
				assert.ok(error.retryAfter > 0);
			}
		});
	});

	describe('rateLimit', () => {
		it('should be an alias for checkRateLimit', async () => {
			const request = { headers: {}, ip: '127.0.0.2' };

			// Should not throw
			await rateLimit(request);
		});
	});

	describe('createRateLimiter', () => {
		it('should create a new rate limiter instance', () => {
			const limiter = createRateLimiter({ points: 5, duration: 10 });
			assert.ok(limiter);
		});

		it('should create isolated limiters', async () => {
			const limiter1 = createRateLimiter({ points: 1, duration: 60 });
			const limiter2 = createRateLimiter({ points: 1, duration: 60 });

			const request = { headers: {}, ip: '192.168.1.200' };

			// Both should succeed independently
			await checkRateLimit(request, { limiter: limiter1 });
			await checkRateLimit(request, { limiter: limiter2 });
		});
	});

	describe('withRateLimit decorator', () => {
		it('should wrap get method', async () => {
			class TestResource {
				async get() {
					return { data: 'test' };
				}
			}

			const RateLimitedResource = withRateLimit({ points: 100, duration: 60 })(TestResource);
			const instance = new RateLimitedResource();

			const request = { headers: {}, ip: '10.0.0.10' };
			const result = await instance.get('target', request);
			assert.deepEqual(result, { data: 'test' });
		});

		it('should wrap post method', async () => {
			class TestResource {
				async post(_target, data) {
					return { received: data };
				}
			}

			const RateLimitedResource = withRateLimit({ points: 100, duration: 60 })(TestResource);
			const instance = new RateLimitedResource();

			const request = { headers: {}, ip: '10.0.0.11' };
			const result = await instance.post('target', { foo: 'bar' }, request);
			assert.deepEqual(result, { received: { foo: 'bar' } });
		});

		it('should only rate limit specified methods', async () => {
			let getCalled = false;
			let postCalled = false;

			class TestResource {
				async get() {
					getCalled = true;
					return {};
				}
				async post() {
					postCalled = true;
					return {};
				}
			}

			// Only rate limit POST
			const RateLimitedResource = withRateLimit({
				points: 1,
				duration: 60,
				methods: ['post'],
			})(TestResource);
			const instance = new RateLimitedResource();

			const request = { headers: {}, ip: '10.0.0.12' };

			// GET should work multiple times (not rate limited)
			await instance.get('target', request);
			await instance.get('target', request);
			assert.ok(getCalled);

			// First POST should work
			await instance.post('target', {}, request);
			assert.ok(postCalled);

			// Second POST should fail
			try {
				await instance.post('target', {}, request);
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}
		});

		it('should throw when rate limit exceeded', async () => {
			class TestResource {
				async get() {
					return {};
				}
			}

			const RateLimitedResource = withRateLimit({ points: 1, duration: 60 })(TestResource);
			const instance = new RateLimitedResource();

			const request = { headers: {}, ip: '10.0.0.13' };

			// First request should succeed
			await instance.get('target', request);

			// Second should fail
			try {
				await instance.get('target', request);
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}
		});
	});

	describe('getRemainingPoints', () => {
		it('should return remaining points', async () => {
			const limiter = createRateLimiter({ points: 10, duration: 60 });
			const request = { headers: {}, ip: '10.0.0.20' };

			// Consume some points
			await checkRateLimit(request, { limiter });
			await checkRateLimit(request, { limiter });

			const remaining = await getRemainingPoints(request, { limiter });
			assert.ok(remaining);
			assert.equal(remaining.remaining, 8);
			assert.ok(remaining.resetMs > 0);
		});

		it('should return null for unknown key', async () => {
			const limiter = createRateLimiter({ points: 10, duration: 60 });
			const request = { headers: {}, ip: '10.0.0.21' };

			const remaining = await getRemainingPoints(request, { limiter });
			assert.equal(remaining, null);
		});
	});

	describe('resetRateLimit', () => {
		it('should reset rate limit for a key', async () => {
			const limiter = createRateLimiter({ points: 1, duration: 60 });
			const request = { headers: {}, ip: '10.0.0.30' };

			// Exhaust limit
			await checkRateLimit(request, { limiter });

			// Should be blocked
			try {
				await checkRateLimit(request, { limiter });
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}

			// Reset
			await resetRateLimit(request, { limiter });

			// Should work again
			const result = await checkRateLimit(request, { limiter });
			assert.ok(result);
		});
	});

	describe('security configuration', () => {
		it('should return current security config', () => {
			configure({ trustProxy: true, trustedProxyDepth: 2 });
			const config = getSecurityConfig();
			assert.equal(config.trustProxy, true);
			assert.equal(config.trustedProxyDepth, 2);
		});

		it('should use trustedProxyDepth to select IP from X-Forwarded-For', async () => {
			// X-Forwarded-For: client, proxy1, proxy2 (rightmost added by our proxy)
			// depth 0 = proxy2 (rightmost), depth 1 = proxy1, depth 2 = client
			configure({ points: 1000, duration: 60, trustProxy: true, trustedProxyDepth: 0 });
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			const request1 = {
				headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' },
				ip: '192.168.60.1',
			};
			const request2 = {
				headers: { 'x-forwarded-for': '4.4.4.4, 5.5.5.5, 3.3.3.3' },
				ip: '192.168.60.1',
			};

			// depth 0 uses rightmost (3.3.3.3) - both requests have same rightmost
			await checkRateLimit(request1, { limiter });

			try {
				await checkRateLimit(request2, { limiter });
				assert.fail('Should have thrown - same rightmost IP');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}
		});

		it('should use deeper proxy depth when configured', async () => {
			// Now use depth 2 to get the client IP (leftmost)
			configure({ points: 1000, duration: 60, trustProxy: true, trustedProxyDepth: 2 });
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			const request1 = {
				headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' },
				ip: '192.168.60.2',
			};
			const request2 = {
				headers: { 'x-forwarded-for': '4.4.4.4, 5.5.5.5, 6.6.6.6' },
				ip: '192.168.60.2',
			};

			// depth 2 uses third from right (1.1.1.1 and 4.4.4.4) - different IPs
			await checkRateLimit(request1, { limiter });
			await checkRateLimit(request2, { limiter }); // Should succeed - different client IPs
		});

		it('should truncate long keys to prevent memory issues', async () => {
			const limiter = createRateLimiter({ points: 1, duration: 60 });

			// Create a very long key via keyGenerator
			const longKey = 'x'.repeat(500);
			const request1 = { headers: {}, ip: '192.168.70.1' };
			const request2 = { headers: {}, ip: '192.168.70.1' };

			await checkRateLimit(request1, {
				limiter,
				keyGenerator: () => longKey,
			});

			// Same long key should be rate limited (key gets truncated consistently)
			try {
				await checkRateLimit(request2, {
					limiter,
					keyGenerator: () => longKey,
				});
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.statusCode, 429);
			}
		});

		it('should handle missing IP gracefully with unknown fallback', async () => {
			const limiter = createRateLimiter({ points: 1000, duration: 60 });
			const request = {
				headers: {},
				// No ip, no connection.remoteAddress
			};

			// Should not throw, uses 'unknown' as fallback
			const result = await checkRateLimit(request, { limiter });
			assert.ok(result);
		});
	});
});
