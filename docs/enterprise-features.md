# Enterprise Features

@nestify/auth-pro provides a comprehensive set of enterprise-grade features to enhance security and user experience.

## Multi-Factor Authentication (MFA)

### TOTP (Time-based One-Time Password)

```typescript
AuthModule.register({
  mfa: {
    enabled: true,
    issuer: 'Your Company Name',
    window: 1, // Time window in minutes
    digits: 6,
    algorithm: 'sha256',
  },
})
```

#### Implementation Example

```typescript
@Injectable()
export class MfaService {
  async generateSecret(userId: string): Promise<string> {
    const secret = authenticator.generateSecret();
    // Store secret securely
    return secret;
  }

  async generateQRCode(secret: string, email: string): Promise<string> {
    const otpauth = authenticator.keyuri(
      email,
      'Your Company Name',
      secret
    );
    return QRCode.toDataURL(otpauth);
  }

  async verifyToken(token: string, secret: string): Promise<boolean> {
    return authenticator.verify({
      token,
      secret,
    });
  }
}
```

## Rate Limiting

### IP-based Rate Limiting

```typescript
AuthModule.register({
  rateLimit: {
    ttl: 60, // Time window in seconds
    limit: 10, // Number of requests per window
    ignoreUserAgents: [], // Optional: array of user agents to ignore
  },
})
```

#### Custom Rate Limit Strategy

```typescript
@Injectable()
export class CustomRateLimitStrategy extends ThrottlerStrategy {
  async handleRequest(
    context: ExecutionContext,
    limit: number,
    ttl: number,
  ): Promise<boolean> {
    const client = context.switchToHttp().getRequest();
    const ip = client.ip;
    // Implement custom rate limiting logic
    return true;
  }
}
```

## Session Management

### Configurable Sessions

```typescript
AuthModule.register({
  session: {
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  },
})
```

### Session Store Options

```typescript
// Redis Store
AuthModule.register({
  session: {
    store: new RedisStore({
      host: 'localhost',
      port: 6379,
    }),
  },
})

// MongoDB Store
AuthModule.register({
  session: {
    store: MongoStore.create({
      mongoUrl: 'mongodb://localhost/sessions',
    }),
  },
})
```

## Refresh Tokens

### Configuration

```typescript
AuthModule.register({
  refreshToken: {
    enabled: true,
    expiresIn: '7d',
    maxRotations: 3,
    length: 32,
  },
})
```

### Implementation Example

```typescript
@Injectable()
export class AuthService {
  async refreshAccessToken(refreshToken: string) {
    // Verify refresh token
    const payload = await this.verifyRefreshToken(refreshToken);
    
    // Generate new access token
    const accessToken = this.jwtService.sign({
      sub: payload.sub,
      email: payload.email,
    });

    // Rotate refresh token if needed
    const newRefreshToken = await this.rotateRefreshToken(refreshToken);

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  }
}
```

## Audit Logging

### Configuration

```typescript
AuthModule.register({
  audit: {
    enabled: true,
    events: ['login', 'logout', 'mfa', 'token_refresh'],
    storage: 'database', // or 'file'
  },
})
```

### Example Implementation

```typescript
@Injectable()
export class AuditService {
  async logEvent(event: AuditEvent) {
    await this.repository.save({
      type: event.type,
      userId: event.userId,
      ip: event.ip,
      userAgent: event.userAgent,
      metadata: event.metadata,
      timestamp: new Date(),
    });
  }

  async queryAuditLogs(filters: AuditLogFilters) {
    return this.repository.find({
      where: filters,
      order: { timestamp: 'DESC' },
    });
  }
}
```

## Password Policies

### Configuration

```typescript
AuthModule.register({
  passwordPolicy: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventReuse: 5, // Remember last 5 passwords
    expiryDays: 90, // Password expires after 90 days
  },
})
```

### Implementation Example

```typescript
@Injectable()
export class PasswordPolicyService {
  validatePassword(password: string): ValidationResult {
    const results = [];
    
    if (password.length < this.config.minLength) {
      results.push('Password too short');
    }
    
    if (this.config.requireUppercase && !/[A-Z]/.test(password)) {
      results.push('Missing uppercase letter');
    }
    
    // Additional validation logic
    
    return {
      valid: results.length === 0,
      errors: results,
    };
  }
}
```

## IP Filtering

### Configuration

```typescript
AuthModule.register({
  ipFilter: {
    enabled: true,
    allowlist: ['192.168.1.0/24'],
    denylist: ['10.0.0.0/8'],
    mode: 'strict', // or 'loose'
  },
})
```

## Best Practices

1. **Security**
   - Use secure session configuration
   - Implement proper rate limiting
   - Enable MFA for sensitive operations
   - Use HTTPS
   - Rotate refresh tokens

2. **Performance**
   - Use appropriate session store
   - Implement caching for rate limiting
   - Optimize database queries
   - Use connection pooling

3. **Monitoring**
   - Set up audit logging
   - Monitor failed authentication attempts
   - Track rate limit violations
   - Monitor session usage

4. **Compliance**
   - Follow data protection regulations
   - Implement proper logging
   - Maintain audit trails
   - Handle user consent

## Troubleshooting

### Common Issues

1. **Rate Limiting**
   - Check rate limit configuration
   - Verify IP detection
   - Review proxy settings

2. **Session Management**
   - Verify session store connection
   - Check session configuration
   - Review cookie settings

3. **MFA**
   - Validate TOTP configuration
   - Check time synchronization
   - Verify secret storage

## API Reference

See [API.md](./API.md) for detailed API documentation.
