# Authentication Providers

## Supported Providers

@nestify/auth-pro supports multiple authentication providers out of the box. Here's a detailed guide for each provider:

## OAuth2 Providers

### Google OAuth2

```typescript
AuthModule.register({
  google: {
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/auth/google/callback',
  },
})
```

#### Setup Steps:
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select existing one
3. Enable Google OAuth2 API
4. Create OAuth2 credentials
5. Add authorized redirect URIs

#### Required Scopes:
- email
- profile

### GitHub OAuth

```typescript
AuthModule.register({
  github: {
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/auth/github/callback',
  },
})
```

#### Setup Steps:
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create new OAuth App
3. Get client ID and secret
4. Add callback URL

#### Required Scopes:
- user:email
- read:user

### Facebook OAuth

```typescript
AuthModule.register({
  facebook: {
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/auth/facebook/callback',
  },
})
```

#### Setup Steps:
1. Go to [Facebook Developers](https://developers.facebook.com)
2. Create new app
3. Add Facebook Login product
4. Configure OAuth settings

#### Required Permissions:
- email
- public_profile

## Best Practices

### Security

1. **Environment Variables**
   ```typescript
   // Use environment variables for sensitive data
   AuthModule.register({
     google: {
       clientID: process.env.GOOGLE_CLIENT_ID,
       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
       callbackURL: process.env.GOOGLE_CALLBACK_URL,
     },
   })
   ```

2. **HTTPS**
   - Always use HTTPS in production
   - Secure callback URLs
   - Validate redirect URIs

3. **Scopes**
   - Request minimum required scopes
   - Document scope usage
   - Handle scope changes

### Error Handling

```typescript
@Get('auth/callback')
async handleCallback(@Req() req) {
  try {
    return await this.authService.authenticate(req);
  } catch (error) {
    if (error.code === 'AUTH_FAILED') {
      // Handle authentication failure
    }
    throw error;
  }
}
```

## Advanced Configuration

### Custom Scopes

```typescript
AuthModule.register({
  google: {
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/auth/google/callback',
    scope: ['email', 'profile', 'calendar.readonly'], // Custom scopes
  },
})
```

### Provider-Specific Options

```typescript
AuthModule.register({
  github: {
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/auth/github/callback',
    scope: ['user:email'],
    allow_signup: false, // GitHub-specific option
  },
})
```

## Troubleshooting

### Common Issues

1. **Invalid Callback URL**
   - Ensure callback URL matches exactly
   - Check for HTTP vs HTTPS
   - Verify domain configuration

2. **Scope Issues**
   - Verify required scopes are configured
   - Check for scope changes in provider
   - Review scope permissions

3. **Rate Limiting**
   - Implement proper caching
   - Handle provider rate limits
   - Add retry logic
