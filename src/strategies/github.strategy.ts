import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { AuthProviderConfig } from '../interfaces/auth-module-options.interface';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(config: AuthProviderConfig) {
    super({
      clientID: config.clientID,
      clientSecret: config.clientSecret,
      callbackURL: config.callbackURL,
      scope: ['user:email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    return {
      provider: 'github',
      providerId: profile.id,
      name: profile.displayName || profile.username,
      email: profile.emails?.[0]?.value,
      picture: profile.photos?.[0]?.value,
      accessToken,
    };
  }
}
