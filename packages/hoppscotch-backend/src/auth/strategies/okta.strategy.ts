import { Strategy } from 'passport-oauth2';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { UserService } from 'src/user/user.service';
import * as O from 'fp-ts/Option';
import * as E from 'fp-ts/Either';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class OktaStrategy extends PassportStrategy(Strategy, 'okta') {
  private readonly logger = new Logger(OktaStrategy.name);

  constructor(
    private authService: AuthService,
    private usersService: UserService,
    private configService: ConfigService,
  ) {
    super({
      authorizationURL: process.env.OKTA_AUTHORIZATION_URL,
      tokenURL: process.env.OKTA_TOKEN_URL,
      clientID: process.env.OKTA_CLIENT_ID,
      clientSecret: process.env.OKTA_CLIENT_SECRET,
      callbackURL: process.env.OKTA_CALLBACK_URL,
      scope: ['openid', 'profile', 'email', 'offline_access'],
      passReqToCallback: true,
      state: true,
    });
    this.logger.log('OktaStrategy initialized with config:', {
      authorizationURL: this.configService.get('INFRA.OKTA_AUTHORIZATION_URL'),
      clientID: this.configService.get('INFRA.OKTA_CLIENT_ID'),
      callbackURL: this.configService.get('INFRA.OKTA_CALLBACK_URL'),
    });
  }

  async validate(
    req: Request,
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (err: any, user?: any) => void
  ) {
    this.logger.debug('OktaStrategy.validate called with:', {
      profile: profile ? { ...profile, _raw: undefined, _json: undefined } : null,
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      accessToken: accessToken,
      refreshToken: refreshToken,
    });

    if (!accessToken) {
      this.logger.error('No access token received from Okta');
      return done(new UnauthorizedException('Failed to obtain access token from Okta'));
    }

    try {
      // Get user info from Okta
      const userInfoResponse = await fetch(process.env.OKTA_USERINFO_URL, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (!userInfoResponse.ok) {
        this.logger.error('Failed to fetch user info from Okta:', await userInfoResponse.text());
        return done(new UnauthorizedException('Failed to fetch user info from Okta'));
      }

      const userInfo = await userInfoResponse.json();
      this.logger.debug('User info from Okta:', userInfo);

      // Construct a proper profile object that matches what we expect
      const oktaProfile = {
        provider: 'okta',
        id: userInfo.sub,
        displayName: userInfo.name || userInfo.preferred_username,
        username: userInfo.preferred_username,
        emails: [{ value: userInfo.email }],
        _raw: JSON.stringify(userInfo),
        _json: userInfo,
      };

      this.logger.debug('Constructed profile:', oktaProfile);

      const user = await this.usersService.findUserByEmail(
        userInfo.email,
      );

      if (O.isNone(user)) {
        this.logger.log('Creating new user for Okta SSO');
        const createdUser = await this.usersService.createUserSSO(
          accessToken,
          refreshToken,
          oktaProfile,
        );
        return done(null, createdUser);
      }

      if (!user.value.displayName || !user.value.photoURL) {
        this.logger.log('Updating user details for existing user');
        const updatedUser = await this.usersService.updateUserDetails(
          user.value,
          oktaProfile,
        );
        if (E.isLeft(updatedUser)) {
          return done(new UnauthorizedException(updatedUser.left));
        }
      }

      const providerAccountExists =
        await this.authService.checkIfProviderAccountExists(user.value, oktaProfile);

      if (O.isNone(providerAccountExists)) {
        this.logger.log('Creating provider account for user');
        await this.usersService.createProviderAccount(
          user.value,
          accessToken,
          refreshToken,
          oktaProfile,
        );
      }

      return done(null, user.value);
    } catch (error) {
      this.logger.error('Error in Okta strategy validate:', error);
      return done(error);
    }
  }
}
