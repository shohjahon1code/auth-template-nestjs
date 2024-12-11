# Getting Started with @nestify/auth-pro

## Installation

```bash
npm install @nestify/auth-pro
# or
yarn add @nestify/auth-pro
```

## Quick Start

### 1. Register the Module

```typescript
import { AuthModule } from '@nestify/auth-pro';

@Module({
  imports: [
    AuthModule.register({
      // Basic configuration
      jwtSecret: process.env.JWT_SECRET,
      jwtExpiresIn: '1h',
      
      // Enable providers
      google: {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/auth/google/callback',
      },
      github: {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: '/auth/github/callback',
      },
      facebook: {
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: '/auth/facebook/callback',
      },
      
      // Enterprise features
      mfa: {
        enabled: true,
        issuer: 'Your Company',
      },
      rateLimit: {
        ttl: 60,
        limit: 10,
      },
    }),
  ],
})
export class AppModule {}
```

### 2. Create User Entity

```typescript
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  password?: string;

  @Column({ nullable: true })
  mfaSecret?: string;

  @Column({ default: false })
  mfaEnabled: boolean;

  @Column({ type: 'json', nullable: true })
  oauth?: {
    provider: string;
    providerId: string;
  };
}
```

### 3. Implement Auth Controller

```typescript
import { Controller, Get, Post, UseGuards, Req } from '@nestjs/common';
import { AuthGuard } from '@nestify/auth-pro';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth() {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  googleAuthCallback(@Req() req) {
    return this.authService.handleOAuthCallback(req);
  }

  @Get('github')
  @UseGuards(AuthGuard('github'))
  githubAuth() {}

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  githubAuthCallback(@Req() req) {
    return this.authService.handleOAuthCallback(req);
  }

  @Get('facebook')
  @UseGuards(AuthGuard('facebook'))
  facebookAuth() {}

  @Get('facebook/callback')
  @UseGuards(AuthGuard('facebook'))
  facebookAuthCallback(@Req() req) {
    return this.authService.handleOAuthCallback(req);
  }

  @Post('mfa/enable')
  @UseGuards(AuthGuard())
  async enableMfa(@Req() req) {
    return this.authService.enableMfa(req.user.id);
  }

  @Post('mfa/verify')
  @UseGuards(AuthGuard())
  async verifyMfa(@Body() body: { token: string }, @Req() req) {
    return this.authService.verifyMfa(req.user.id, body.token);
  }
}
```

### 4. Configure Environment Variables

Create a `.env` file:

```env
# JWT Configuration
JWT_SECRET=your-secure-secret
JWT_EXPIRES_IN=1h

# OAuth Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/db

# Session
SESSION_SECRET=your-session-secret

# Redis (for rate limiting)
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Basic Usage Examples

### Local Authentication

```typescript
// Login
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123',
  }),
});

const { accessToken } = await response.json();
```

### OAuth Authentication

```typescript
// Redirect to Google login
window.location.href = '/auth/google';

// Handle callback in your frontend
if (window.location.pathname === '/auth/google/callback') {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  // Handle the OAuth callback
}

// Similarly for GitHub
window.location.href = '/auth/github';

// And Facebook
window.location.href = '/auth/facebook';
```

## Advanced Configuration

### Custom User Service

```typescript
@Injectable()
export class CustomUserService implements AuthUserService {
  async findById(id: string): Promise<User> {
    // Implement user lookup
  }

  async findByEmail(email: string): Promise<User> {
    // Implement user lookup
  }

  async createUser(data: CreateUserDto): Promise<User> {
    // Implement user creation
  }
}

// Register with custom service
AuthModule.register({
  userService: CustomUserService,
  // ... other options
})
```

### Custom Auth Guards

```typescript
@Injectable()
export class CustomAuthGuard extends AuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Implement custom authentication logic
    return super.canActivate(context);
  }
}
```

## Next Steps

1. Check out [Providers Documentation](./providers.md) for setting up additional authentication providers
2. Explore [Enterprise Features](./enterprise-features.md) for advanced security options
3. Review [Best Practices](./best-practices.md) for security and performance recommendations
4. See [API Reference](./api.md) for detailed API documentation

## Support

- GitHub Issues: [Report a bug](https://github.com/nestify/auth-pro/issues)
- Documentation: [Full documentation](https://docs.nestify.dev/auth-pro)
- Community: [Discord Server](https://discord.gg/nestify)
