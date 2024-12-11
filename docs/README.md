# @nestify/auth-pro Documentation

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Concepts](#core-concepts)
3. [Authentication Providers](#authentication-providers)
4. [Enterprise Features](#enterprise-features)
5. [API Reference](#api-reference)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

## Getting Started

### Installation

```bash
npm install @nestify/auth-pro
```

### Quick Start

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from '@nestify/auth-pro';

@Module({
  imports: [
    AuthModule.register({
      jwtSecret: process.env.JWT_SECRET,
      google: {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'http://localhost:3000/auth/google/callback',
      },
    }),
  ],
})
export class AppModule {}
```

## Core Concepts

### Authentication Flow

1. **OAuth2 Flow**:
   ```
   User -> Your App -> Auth Provider -> Callback -> JWT Token
   ```

2. **JWT Authentication**:
   - Access tokens for API authorization
   - Configurable expiration
   - Refresh token support

3. **Session Management**:
   - Optional session support
   - Configurable session duration
   - Session invalidation

## Authentication Providers

### Supported Providers

1. **Google OAuth2**
   ```typescript
   AuthModule.register({
     google: {
       clientID: 'your-client-id',
       clientSecret: 'your-client-secret',
       callbackURL: '/auth/google/callback',
     },
   })
   ```

2. **GitHub OAuth**
   ```typescript
   AuthModule.register({
     github: {
       clientID: 'your-client-id',
       clientSecret: 'your-client-secret',
       callbackURL: '/auth/github/callback',
     },
   })
   ```

3. **Facebook OAuth**
   ```typescript
   AuthModule.register({
     facebook: {
       clientID: 'your-client-id',
       clientSecret: 'your-client-secret',
       callbackURL: '/auth/facebook/callback',
     },
   })
   ```

[View all supported providers →](./providers.md)

## Enterprise Features

### Multi-Factor Authentication (MFA)

```typescript
// Configuration
AuthModule.register({
  mfa: {
    enabled: true,
    issuer: 'Your App Name',
  },
})

// Usage in your service
@Injectable()
class AuthService {
  constructor(private mfaService: MFAService) {}

  async setupMFA(userId: string) {
    const { secret, qrCode } = await this.mfaService.generateSecret(
      userId,
      'Your App'
    );
    // Store secret securely
    return qrCode;
  }
}
```

### Rate Limiting

```typescript
// Global configuration
AuthModule.register({
  rateLimit: {
    enabled: true,
    maxAttempts: 5,
    timeWindow: 60000, // 1 minute
  },
})

// Per-endpoint configuration
@UseGuards(RateLimitGuard)
@Post('login')
async login() {
  // This endpoint is protected
}
```

### Session Management

```typescript
AuthModule.register({
  session: {
    enabled: true,
    maxAge: 86400000, // 24 hours
  },
})
```

[View all enterprise features →](./enterprise.md)

## API Reference

### AuthModuleOptions

```typescript
interface AuthModuleOptions {
  // JWT Configuration
  jwtSecret: string;
  jwtExpiresIn?: string;

  // MFA Configuration
  mfa?: {
    enabled: boolean;
    issuer?: string;
  };

  // Rate Limiting
  rateLimit?: {
    enabled: boolean;
    maxAttempts?: number;
    timeWindow?: number;
  };

  // Session Management
  session?: {
    enabled: boolean;
    maxAge?: number;
  };

  // OAuth Providers
  google?: AuthProviderConfig;
  github?: AuthProviderConfig;
  facebook?: AuthProviderConfig;
  // ... other providers
}
```

[View full API reference →](./api-reference.md)

## Best Practices

### Security Best Practices

1. **Environment Variables**
   ```typescript
   // Don't hardcode secrets
   ❌ jwtSecret: 'my-secret'
   ✅ jwtSecret: process.env.JWT_SECRET
   ```

2. **Rate Limiting**
   ```typescript
   // Protect authentication endpoints
   AuthModule.register({
     rateLimit: {
       enabled: true,
       maxAttempts: 5,
       timeWindow: 60000,
     },
   })
   ```

3. **MFA Implementation**
   ```typescript
   // Store MFA secrets securely
   const { secret } = await mfaService.generateSecret();
   await secureStorage.encrypt(secret);
   ```

### Performance Optimization

1. **JWT Configuration**
   ```typescript
   AuthModule.register({
     jwtExpiresIn: '15m', // Short-lived tokens
     refreshToken: {
       enabled: true,
       expiresIn: '7d',
     },
   })
   ```

2. **Session Management**
   ```typescript
   AuthModule.register({
     session: {
       enabled: true,
       maxAge: 3600000, // 1 hour
     },
   })
   ```

[View all best practices →](./best-practices.md)

## Troubleshooting

### Common Issues

1. **Rate Limiting Issues**
   ```typescript
   // Problem: Too many requests
   // Solution: Adjust rate limiting
   AuthModule.register({
     rateLimit: {
       maxAttempts: 10, // Increase limit
       timeWindow: 300000, // 5 minutes
     },
   })
   ```

2. **JWT Token Issues**
   ```typescript
   // Problem: Tokens expire too quickly
   // Solution: Adjust expiration time
   AuthModule.register({
     jwtExpiresIn: '1h',
   })
   ```

[View troubleshooting guide →](./troubleshooting.md)

## Contributing

We welcome contributions! Please see our [contributing guide](./CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](./LICENSE) for details.
