import { Scalar } from '@nestjs/graphql';
import { Kind, ASTNode } from 'graphql';

@Scalar('Date')
export class DateScalar {
  description = 'Date custom scalar type';

  parseValue(value: Date) {
    return new Date(value); // value from the client
  }

  serialize(value: Date) {
    return value.getTime(); // value sent to the client
  }

  parseLiteral(ast: ASTNode) {
    if (ast.kind === Kind.INT) {
      return parseInt(ast.value, 10); // ast value is always in string format
    }
    return null;
  }
}
