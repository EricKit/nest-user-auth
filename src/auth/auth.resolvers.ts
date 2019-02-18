import { Resolver, Args, Query } from '@nestjs/graphql';
import { LoginUserInput, LoginResult } from '../graphql.classes';
import { AuthService } from './auth.service';
import { UnauthorizedException } from '@nestjs/common';

@Resolver('Auth')
export class AuthResolver {
  constructor(private authService: AuthService) {}

  @Query('login')
  async login(@Args('user') user: LoginUserInput): Promise<LoginResult | null> {
    const result = await this.authService.validateUserByPassword(user);
    if (result) return result;
    throw new UnauthorizedException();
  }
}
