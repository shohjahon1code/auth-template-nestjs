import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-facebook';
import { AuthProviderConfig } from '../interfaces/auth-module-options.interface';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(config: AuthProviderConfig) {
    super({
      clientID: config.clientID,
      clientSecret: config.clientSecret,
      callbackURL: config.callbackURL,
      profileFields: ['id', 'emails', 'name', 'photos'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    return {
      provider: 'facebook',
      providerId: profile.id,
      name: profile.name.givenName + ' ' + profile.name.familyName,
      email: profile.emails[0]?.value,
      picture: profile.photos[0]?.value,
      accessToken,
    };
  }
}
