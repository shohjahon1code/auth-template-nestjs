# 🚀 @nestify/auth-pro

Enterprise-grade authentication solution for NestJS applications.

![npm version](https://img.shields.io/npm/v/@nestify/auth-pro)
![downloads](https://img.shields.io/npm/dm/@nestify/auth-pro)
![license](https://img.shields.io/npm/l/@nestify/auth-pro)

## ✨ Features

### Authentication Providers
- 🔐 Multiple OAuth2 providers supported:
  - Google
  - GitHub
  - Facebook
  - Twitter
  - Microsoft (Azure AD)
  - Apple
  - LinkedIn
  - Discord
  - GitLab
  - Bitbucket

### Enterprise Features
- 🛡️ Multi-Factor Authentication (MFA)
  - TOTP (Time-based One-Time Password)
  - QR code generation
  - Custom issuer support
- 🔒 Rate Limiting
  - IP-based rate limiting
  - Configurable time windows
  - Customizable attempt limits
- 🎯 Session Management
  - Configurable session duration
  - Session invalidation
- 🔄 Refresh Tokens
  - Configurable expiration
  - Token rotation
- 📚 Auto-generated Swagger documentation
- 🎯 100% TypeScript support
- ⚡️ Zero-config defaults

## 🚀 Quick Start

### Installation

```bash
npm install @nestify/auth-pro
```

### Basic Setup

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from '@nestify/auth-pro';

@Module({
  imports: [
    AuthModule.register({
      jwtSecret: 'your-jwt-secret',
      jwtExpiresIn: '1h',
      // Enable MFA
      mfa: {
        enabled: true,
        issuer: 'Your App',
      },
      // Enable rate limiting
      rateLimit: {
        enabled: true,
        maxAttempts: 5,
        timeWindow: 60000, // 1 minute
      },
      // Configure providers
      google: {
        clientID: 'your-google-client-id',
        clientSecret: 'your-google-client-secret',
        callbackURL: 'http://localhost:3000/auth/google/callback',
      },
      github: {
        clientID: 'your-github-client-id',
        clientSecret: 'your-github-client-secret',
        callbackURL: 'http://localhost:3000/auth/github/callback',
      },
      facebook: {
        clientID: 'your-facebook-client-id',
        clientSecret: 'your-facebook-client-secret',
        callbackURL: 'http://localhost:3000/auth/facebook/callback',
      },
    }),
  ],
})
export class AppModule {}
```

### Enterprise Features Usage

#### Multi-Factor Authentication

```typescript
import { MFAService } from '@nestify/auth-pro';

@Injectable()
export class YourService {
  constructor(private mfaService: MFAService) {}

  async setupMFA(username: string) {
    const { secret, qrCode } = await this.mfaService.generateSecret(
      username,
      'Your App'
    );
    // Store secret securely and return QR code to user
    return { qrCode };
  }

  verifyMFAToken(token: string, secret: string) {
    return this.mfaService.verifyToken(token, secret);
  }
}
```

#### Rate Limiting

```typescript
import { UseGuards } from '@nestjs/common';
import { RateLimitGuard } from '@nestify/auth-pro';

@Controller('auth')
@UseGuards(RateLimitGuard)
export class AuthController {
  // Your endpoints will be protected from brute force attacks
}
```

## Available Endpoints

### OAuth2 Authentication
- Google:
  - GET `/auth/google` - Initiates Google OAuth2 authentication
  - GET `/auth/google/callback` - Google OAuth2 callback URL
- GitHub:
  - GET `/auth/github` - Initiates GitHub OAuth authentication
  - GET `/auth/github/callback` - GitHub OAuth callback URL
- Facebook:
  - GET `/auth/facebook` - Initiates Facebook OAuth authentication
  - GET `/auth/facebook/callback` - Facebook OAuth callback URL
- And more providers...

### MFA Endpoints
- POST `/auth/mfa/generate` - Generate MFA secret and QR code
- POST `/auth/mfa/verify` - Verify MFA token

## Response Format

After successful authentication, you'll receive a response in the following format:

```json
{
  "access_token": "jwt-token-here",
  "refresh_token": "refresh-token-here",
  "user": {
    "email": "user@example.com",
    "name": "User Name",
    "picture": "profile-picture-url",
    "provider": "google|github|facebook|etc"
  }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
