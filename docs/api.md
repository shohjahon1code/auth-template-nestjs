# API Reference

## AuthModule

### Configuration Options

```typescript
interface AuthModuleOptions {
  // Basic Configuration
  jwtSecret: string;
  jwtExpiresIn?: string;
  userService?: Type<AuthUserService>;
  
  // OAuth Providers
  google?: OAuthProviderOptions;
  github?: OAuthProviderOptions;
  facebook?: OAuthProviderOptions;
  
  // Enterprise Features
  mfa?: MFAOptions;
  rateLimit?: RateLimitOptions;
  session?: SessionOptions;
  refreshToken?: RefreshTokenOptions;
  audit?: AuditOptions;
  passwordPolicy?: PasswordPolicyOptions;
  ipFilter?: IPFilterOptions;
}
```

### Provider Options

```typescript
interface OAuthProviderOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string[];
  authorizationURL?: string;
  tokenURL?: string;
  profileURL?: string;
  state?: boolean;
}
```

### MFA Options

```typescript
interface MFAOptions {
  enabled: boolean;
  issuer?: string;
  window?: number;
  digits?: number;
  algorithm?: 'sha1' | 'sha256' | 'sha512';
  qrCodeProvider?: Type<QRCodeProvider>;
}
```

### Rate Limit Options

```typescript
interface RateLimitOptions {
  ttl: number;
  limit: number;
  ignoreUserAgents?: string[];
  errorMessage?: string;
  strategy?: Type<ThrottlerStrategy>;
}
```

### Session Options

```typescript
interface SessionOptions {
  secret: string;
  name?: string;
  resave?: boolean;
  saveUninitialized?: boolean;
  cookie?: CookieOptions;
  store?: SessionStore;
}
```

### Refresh Token Options

```typescript
interface RefreshTokenOptions {
  enabled: boolean;
  expiresIn?: string;
  maxRotations?: number;
  length?: number;
  strategy?: Type<RefreshTokenStrategy>;
}
```

### Password Policy Options

```typescript
interface PasswordPolicyOptions {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  preventReuse?: number;
  expiryDays?: number;
}
```

## Services

### AuthService

```typescript
class AuthService {
  constructor(
    private readonly userService: AuthUserService,
    private readonly jwtService: JwtService,
    private readonly mfaService?: MFAService,
  ) {}

  async login(credentials: LoginDto): Promise<AuthResponse>;
  async register(userData: RegisterDto): Promise<AuthResponse>;
  async validateUser(email: string, password: string): Promise<User>;
  async refreshToken(token: string): Promise<AuthResponse>;
  async logout(userId: string): Promise<void>;
}
```

### MFAService

```typescript
class MFAService {
  constructor(
    private readonly options: MFAOptions,
    private readonly qrCodeProvider: QRCodeProvider,
  ) {}

  async generateSecret(userId: string): Promise<string>;
  async generateQRCode(secret: string, email: string): Promise<string>;
  async verifyToken(token: string, secret: string): Promise<boolean>;
  async enableMFA(userId: string): Promise<void>;
  async disableMFA(userId: string): Promise<void>;
}
```

### AuditService

```typescript
class AuditService {
  constructor(
    private readonly options: AuditOptions,
    private readonly repository: AuditLogRepository,
  ) {}

  async logEvent(event: AuditEvent): Promise<void>;
  async queryAuditLogs(filters: AuditLogFilters): Promise<AuditLog[]>;
  async getEventsByUser(userId: string): Promise<AuditLog[]>;
  async getEventsByType(type: string): Promise<AuditLog[]>;
}
```

## Guards

### AuthGuard

```typescript
class AuthGuard implements CanActivate {
  constructor(private readonly strategy?: string) {}

  async canActivate(context: ExecutionContext): Promise<boolean>;
}
```

### MFAGuard

```typescript
class MFAGuard implements CanActivate {
  constructor(private readonly mfaService: MFAService) {}

  async canActivate(context: ExecutionContext): Promise<boolean>;
}
```

### RateLimitGuard

```typescript
class RateLimitGuard implements CanActivate {
  constructor(
    private readonly options: RateLimitOptions,
    private readonly strategy: ThrottlerStrategy,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean>;
}
```

## Decorators

### Auth Decorators

```typescript
// Protect routes with authentication
@UseGuards(AuthGuard())
@Controller('protected')
export class ProtectedController {}

// Require specific provider
@UseGuards(AuthGuard('google'))
@Get('google')
googleAuth() {}

// Require MFA
@UseGuards(MFAGuard)
@Get('sensitive')
sensitiveData() {}

// Apply rate limiting
@UseGuards(RateLimitGuard)
@Get('api')
apiEndpoint() {}
```

### Custom Decorators

```typescript
// Get current user
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);

// Roles decorator
export const Roles = (...roles: string[]) => SetMetadata('roles', roles);
```

## Interfaces

### User Interface

```typescript
interface User {
  id: string;
  email: string;
  password?: string;
  mfaSecret?: string;
  mfaEnabled: boolean;
  oauth?: {
    provider: string;
    providerId: string;
  };
}
```

### Auth Response

```typescript
interface AuthResponse {
  accessToken: string;
  refreshToken?: string;
  user: User;
  mfaRequired?: boolean;
}
```

### Audit Log

```typescript
interface AuditLog {
  id: string;
  type: string;
  userId: string;
  ip: string;
  userAgent: string;
  metadata: Record<string, any>;
  timestamp: Date;
}
```

## Error Handling

### Auth Errors

```typescript
class AuthenticationError extends Error {
  constructor(message: string, public code: string) {
    super(message);
  }
}

class MFARequiredError extends AuthenticationError {
  constructor() {
    super('MFA verification required', 'MFA_REQUIRED');
  }
}

class InvalidTokenError extends AuthenticationError {
  constructor() {
    super('Invalid or expired token', 'INVALID_TOKEN');
  }
}
```

## Events

### Auth Events

```typescript
interface AuthEvent {
  type: string;
  userId: string;
  metadata?: Record<string, any>;
}

class UserLoggedInEvent implements AuthEvent {
  type = 'USER_LOGGED_IN';
  constructor(
    public userId: string,
    public provider: string,
  ) {}
}

class MFAEnabledEvent implements AuthEvent {
  type = 'MFA_ENABLED';
  constructor(public userId: string) {}
}
```

## Utilities

### Password Utilities

```typescript
class PasswordUtils {
  static async hash(password: string): Promise<string>;
  static async verify(password: string, hash: string): Promise<boolean>;
  static generateTemporary(length?: number): string;
  static validatePolicy(password: string, policy: PasswordPolicyOptions): boolean;
}
```

### Token Utilities

```typescript
class TokenUtils {
  static generateRefreshToken(length?: number): string;
  static parseToken(token: string): TokenPayload;
  static validateToken(token: string, secret: string): boolean;
  static rotateToken(oldToken: string): string;
}
