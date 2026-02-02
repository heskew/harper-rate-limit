# harper-rate-limit

Rate limiting plugin for Harper applications, powered by [rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible).

## Installation

```bash
npm install harper-rate-limit
```

## Configuration

Add to your `config.yaml`:

```yaml
harper-rate-limit:
  package: 'harper-rate-limit'
  points: 100 # Number of requests allowed
  duration: 60 # Per 60 seconds
  blockDuration: 0 # Block duration when exceeded (0 = until points restored)
  keyPrefix: 'rl' # Key prefix for store
  trustProxy: false # Trust X-Forwarded-For headers (see Security section)
  trustedProxyDepth: 0 # Which proxy hop to trust (0 = rightmost)
```

## Usage

### 1. Decorator-Based Rate Limiting

Apply the `@withRateLimit` decorator to protect Resource classes:

```typescript
import { withRateLimit } from 'harper-rate-limit';

// Use default limits from config
@withRateLimit()
export class MyResource extends Resource {
	async get(target: string, request: any) {
		// Rate limit checked automatically before this runs
		return { data: 'Hello' };
	}
}

// Custom limits for this resource
@withRateLimit({ points: 10, duration: 60 })
export class StrictResource extends Resource {
	async post(target: string, data: any, request: any) {
		// Only 10 requests per minute allowed
		return { success: true };
	}
}

// Rate limit by authenticated user instead of IP
@withRateLimit({ byUser: true })
export class UserResource extends Resource {
	// Each user gets their own rate limit bucket
}

// Only rate limit specific methods
@withRateLimit({ methods: ['post', 'put'] })
export class PartialResource extends Resource {
	async get() {
		// GET is not rate limited
	}
	async post() {
		// POST is rate limited
	}
}
```

### 2. Manual Rate Limiting

For more control, use the `rateLimit` function directly:

```typescript
import { rateLimit, checkRateLimit } from 'harper-rate-limit';

export class CustomResource extends Resource {
	async post(target: string, data: any, request: any) {
		// Manual rate limit check
		await rateLimit(request, { points: 5, duration: 60 });

		// Or with full result
		const result = await checkRateLimit(request);
		console.log(`Remaining: ${result.remainingPoints}`);

		return { success: true };
	}
}
```

### 3. Custom Key Generation

Rate limit by custom criteria:

```typescript
@withRateLimit({
	keyGenerator: (request) => {
		// Rate limit by API key
		return `apikey:${request.headers['x-api-key']}`;
	},
})
export class ApiResource extends Resource {}
```

### 4. Separate Limiters

Create isolated rate limiters for different endpoints:

```typescript
import { createRateLimiter, withRateLimit } from 'harper-rate-limit';

// Strict limiter for auth endpoints
const authLimiter = createRateLimiter({ points: 5, duration: 300 });

@withRateLimit({ limiter: authLimiter })
export class LoginResource extends Resource {}
```

## API

### `withRateLimit(options?)`

Class decorator for automatic rate limiting.

Options:

- `points`: Number of requests allowed (default: from config)
- `duration`: Time window in seconds (default: from config)
- `blockDuration`: Block duration when exceeded
- `pointsToConsume`: Points per request (default: 1)
- `byUser`: Use user ID instead of IP (default: false)
- `keyGenerator`: Custom function to generate rate limit key
- `limiter`: Custom RateLimiterMemory instance
- `methods`: Array of methods to rate limit (default: all)

### `rateLimit(request, options?)`

Manual rate limit check. Throws 429 error if exceeded.

### `checkRateLimit(request, options?)`

Check rate limit and return result. Throws 429 if exceeded.

### `createRateLimiter(options)`

Create a custom rate limiter instance.

### `getRemainingPoints(request, options?)`

Get remaining points for the current key. Returns `{ remaining, resetMs }` or null.

### `resetRateLimit(request, options?)`

Reset rate limit for the current key.

## Error Response

When rate limit is exceeded, a 429 error is thrown:

```json
{
	"error": "Too many requests. Please try again later.",
	"statusCode": 429,
	"retryAfter": 30
}
```

## Combining with CSRF Protection

```typescript
import { withCsrfProtection } from 'harper-csrf';
import { withRateLimit } from 'harper-rate-limit';

@withRateLimit({ points: 100, duration: 60 })
@withCsrfProtection
export class SecureResource extends Resource {
	async post(target: string, data: any, request: any) {
		// Both rate limiting and CSRF protection applied
		return { success: true };
	}
}
```

## Security

### Proxy Header Trust

By default, this plugin does **not** trust proxy headers (`X-Forwarded-For`, `X-Real-IP`). This prevents attackers from bypassing rate limits by spoofing these headers.

**If Harper is behind a reverse proxy** (nginx, AWS ALB, Cloudflare, etc.), you must enable `trustProxy` for accurate client identification:

```yaml
harper-rate-limit:
  package: 'harper-rate-limit'
  trustProxy: true # Enable proxy header trust
  trustedProxyDepth: 0 # Which IP to use from X-Forwarded-For
```

**trustedProxyDepth** controls which IP address to extract from the `X-Forwarded-For` header:

- `0` (default): Use the rightmost IP (added by your closest proxy)
- `1`: Use second from right (skip one proxy)
- `2`: Skip two proxies, etc.

Use depth `0` when your proxy appends to the header. Use higher values if you have multiple trusted proxies in your infrastructure.

**Warning**: Only enable `trustProxy` when Harper is behind a trusted reverse proxy. Enabling it when directly exposed to the internet allows attackers to bypass rate limiting.

### Key Sanitization

All rate limit keys are automatically truncated to 256 characters to prevent memory exhaustion attacks from malicious input.

## Performance Considerations

### In-Memory Storage

This plugin uses `RateLimiterMemory` which stores rate limit counters in the Node.js process memory. This has important implications:

**Single Instance**: Rate limits are not shared across multiple Harper instances. In a clustered deployment, each instance maintains its own counters. A client could potentially make `N × limit` requests where `N` is the number of instances.

**Process Restart**: Rate limit counters are lost when the process restarts.

**Memory Usage**: Each unique key consumes memory. With high-cardinality keys (many unique IPs/users), memory usage grows accordingly.

### When to Use External Stores

For production deployments requiring:

- Shared rate limits across instances
- Persistence across restarts
- Distributed rate limiting

Consider using a custom limiter with an external store:

```typescript
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { createClient } from 'redis';

const redisClient = createClient({ url: 'redis://localhost:6379' });
await redisClient.connect();

const redisLimiter = new RateLimiterRedis({
	storeClient: redisClient,
	points: 100,
	duration: 60,
});

@withRateLimit({ limiter: redisLimiter })
export class MyResource extends Resource {}
```

See [rate-limiter-flexible documentation](https://github.com/animir/node-rate-limiter-flexible) for available stores (Redis, Memcached, MongoDB, PostgreSQL, etc.).

## Requirements

- Harper 4.7.0+
- Node.js 22+

## License

MIT
