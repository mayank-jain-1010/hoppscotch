import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthProvider, authProviderCheck } from '../helper';
import { Observable } from 'rxjs';
import { AUTH_PROVIDER_NOT_SPECIFIED } from 'src/errors';
import { ConfigService } from '@nestjs/config';
import { throwHTTPErr } from 'src/utils';

@Injectable()
export class OktaSSOGuard extends AuthGuard('okta') implements CanActivate {
  private readonly logger = new Logger(OktaSSOGuard.name);

  constructor(private readonly configService: ConfigService) {
    super();
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const allowedProviders = this.configService.get('INFRA.VITE_ALLOWED_AUTH_PROVIDERS');
    this.logger.debug('Allowed auth providers:', allowedProviders);
    
    // For development/testing, you can temporarily bypass the provider check
    // by uncommenting the following line:
    // return super.canActivate(context);

    if (
      !authProviderCheck(
        AuthProvider.OKTA,
        allowedProviders,
      )
    ) {
      this.logger.error('Okta is not in allowed providers:', allowedProviders);
      throwHTTPErr({ message: AUTH_PROVIDER_NOT_SPECIFIED, statusCode: 404 });
    }

    return super.canActivate(context);
  }

  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    const redirectUri = req.query.redirect_uri || this.configService.get('REDIRECT_URL');

    return {
      state: {
        redirect_uri: redirectUri,
      },
      passReqToCallback: true,
    };
  }
}