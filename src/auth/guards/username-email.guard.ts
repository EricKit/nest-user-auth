import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';
import { GqlExecutionContext } from '@nestjs/graphql';
import { User } from '../../graphql.classes';
import { UsersService } from '../../users/users.service';

// Check if username in field for query matches authenticated user's username
// or if the user is admin
@Injectable()
export class UsernameEmailGuard implements CanActivate {
  constructor(private usersService: UsersService) {}

  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    if (request.user) {
      const user = <User> request.user;
      if (this.usersService.isAdmin(user.permissions)) return true;
      const args = ctx.getArgs();
      if (args.username) {
        return args.username === user.username;
      } else if (args.email) {
        return args.email === user.email;
      }
    }
    return false;
  }
}
