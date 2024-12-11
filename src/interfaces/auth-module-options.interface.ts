import { ModuleMetadata } from '@nestjs/common';

export interface AuthProviderConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface AuthModuleOptions {
  jwtSecret: string;
  jwtExpiresIn?: string; // Optional JWT expiration time
  refreshToken?: {
    enabled: boolean;
    expiresIn?: string;
  };
  rateLimit?: {
    enabled: boolean;
    maxAttempts?: number;
    timeWindow?: number; // in milliseconds
  };
  mfa?: {
    enabled: boolean;
    issuer?: string;
  };
  session?: {
    enabled: boolean;
    maxAge?: number; // in milliseconds
  };
  google?: AuthProviderConfig;
  github?: AuthProviderConfig;
  facebook?: AuthProviderConfig;
  twitter?: AuthProviderConfig;
  microsoft?: AuthProviderConfig & {
    tenantId?: string;
  };
  apple?: AuthProviderConfig;
  linkedin?: AuthProviderConfig;
  discord?: AuthProviderConfig;
  gitlab?: AuthProviderConfig;
  bitbucket?: AuthProviderConfig;
}

export interface AuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useFactory: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
  inject?: any[];
}
