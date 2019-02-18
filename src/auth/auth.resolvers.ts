import { Resolver, Args, Query } from '@nestjs/graphql';
import { LoginUserInput, LoginResult } from '../graphql.classes';
import { AuthService } from './auth.service';

@Resolver('Auth')
export class AuthResolver {
  constructor(private authService: AuthService) {}

  @Query('login')
  async login(@Args('user') user: LoginUserInput): Promise<LoginResult | null> {
    return await this.authService.validateUserByPassword(user);
  }
}
