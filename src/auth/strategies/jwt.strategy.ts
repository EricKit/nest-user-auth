import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';
import { PassportStrategy } from '@nestjs/passport';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { JWT_SECRET } from '../../../secrets';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: JWT_SECRET,
    });
  }

  // TODO: Where is any documentation on this function? Little on the nest documentation
  async validate(payload: JwtPayload) {
    // This is called to validate the user in the token exists
    const user = await this.authService.validateUserByJwt(payload);

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
