import { DynamicModule, Module, Provider } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { GoogleStrategy } from './strategies/google.strategy';
import { GithubStrategy } from './strategies/github.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { MFAService } from './services/mfa.service';
import { RateLimitGuard } from './guards/rate-limit.guard';
import {
  AuthModuleOptions,
  AuthModuleAsyncOptions,
} from './interfaces/auth-module-options.interface';

@Module({})
export class AuthModule {
  static register(options: AuthModuleOptions): DynamicModule {
    const providers = AuthModule.createProviders(options);
    const imports = AuthModule.createImports(options);

    return {
      module: AuthModule,
      imports,
      providers: [AuthService, MFAService, RateLimitGuard, ...providers],
      controllers: [AuthController],
      exports: [AuthService, MFAService],
    };
  }

  static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: 'temp-secret', // Will be overwritten by async config
          signOptions: { expiresIn: '1h' },
        }),
        ThrottlerModule.forRoot([{
          name: 'short',
          ttl: 60000,
          limit: 10,
        }]),
        ...(options.imports || []),
      ],
      providers: [
        {
          provide: 'AUTH_MODULE_OPTIONS',
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        AuthService,
        MFAService,
        RateLimitGuard,
        {
          provide: GoogleStrategy,
          useFactory: (config: AuthModuleOptions) =>
            config.google ? new GoogleStrategy(config.google) : null,
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: GithubStrategy,
          useFactory: (config: AuthModuleOptions) =>
            config.github ? new GithubStrategy(config.github) : null,
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: FacebookStrategy,
          useFactory: (config: AuthModuleOptions) =>
            config.facebook ? new FacebookStrategy(config.facebook) : null,
          inject: ['AUTH_MODULE_OPTIONS'],
        },
      ],
      controllers: [AuthController],
      exports: [AuthService, MFAService],
    };
  }

  private static createProviders(options: AuthModuleOptions): Provider[] {
    const providers: Provider[] = [];

    if (options.google) {
      providers.push({
        provide: GoogleStrategy,
        useValue: new GoogleStrategy(options.google),
      });
    }

    if (options.github) {
      providers.push({
        provide: GithubStrategy,
        useValue: new GithubStrategy(options.github),
      });
    }

    if (options.facebook) {
      providers.push({
        provide: FacebookStrategy,
        useValue: new FacebookStrategy(options.facebook),
      });
    }

    return providers;
  }

  private static createImports(options: AuthModuleOptions): any[] {
    const imports = [
      PassportModule.register({ defaultStrategy: 'jwt' }),
      JwtModule.register({
        secret: options.jwtSecret,
        signOptions: { expiresIn: options.jwtExpiresIn || '1h' },
      }),
    ];

    if (options.rateLimit?.enabled) {
      imports.push(
        ThrottlerModule.forRoot([{
          name: 'short',
          ttl: options.rateLimit.timeWindow || 60000,
          limit: options.rateLimit.maxAttempts || 10,
        }]),
      );
    }

    return imports;
  }
}
