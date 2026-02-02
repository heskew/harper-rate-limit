# Claude Instructions for harper-rate-limit

## Project Overview

A rate limiting plugin for Harper applications using `rate-limiter-flexible`:

- `@withRateLimit()` class decorator for automatic rate limiting
- Manual `rateLimit()` and `checkRateLimit()` functions
- Configurable by IP, user, or custom key

## Key Patterns

### In-Memory Rate Limiting

Uses `RateLimiterMemory` from `rate-limiter-flexible`. Each decorator invocation can create its own limiter for isolated limits.

### Decorator Pattern

```typescript
@withRateLimit({ points: 10, duration: 60 })
export class MyResource extends Resource {
	// All methods rate limited
}

@withRateLimit({ methods: ['post'] })
export class PartialResource extends Resource {
	// Only POST is rate limited
}
```

### Key Generation

Default: IP address from `request.ip` or `connection.remoteAddress`. Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are only used when `trustProxy: true` is configured.

Options:

- `trustProxy: true` - Trust proxy headers for IP detection (must be behind trusted proxy)
- `trustedProxyDepth: 0` - Which IP to use from X-Forwarded-For (0 = rightmost)
- `byUser: true` - Use session user ID instead of IP
- `keyGenerator: (req) => string` - Custom key function

## Project Structure

```
src/
  index.ts        # All exports: decorator, functions, types
dist/             # Compiled output
test/
  index.test.js   # Tests using node:test
```

## Building & Testing

```bash
npm install       # Install dependencies
npm run build     # Compile TypeScript
npm test          # Run tests
npm run lint      # ESLint check
npm run format:check  # Prettier check
```

## Code Style

Uses `@harperdb/code-guidelines` for ESLint and Prettier configuration.

## CI/CD

- `.github/workflows/checks.yml` - Lint, format, test on Node 22/24 (with Socket Firewall)
- `.github/workflows/npm-publish.yml` - Publish to npm on release (with Socket Firewall)

## Dependencies

- `rate-limiter-flexible` - Core rate limiting library (in-memory store)
