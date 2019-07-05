import { Scalar } from '@nestjs/graphql';
import { Kind, ASTNode } from 'graphql';
import { Types } from 'mongoose';

@Scalar('ObjectId')
export class ObjectIdScalar {
  description = 'Mongo ObjectId scalar type';

  parseValue(value: string) {
    return new Types.ObjectId(value); // value from the client
  }

  serialize(value: Types.ObjectId) {
    return value.toHexString(); // value sent to the client
  }

  parseLiteral(ast: ASTNode) {
    if (ast.kind === Kind.STRING) {
      return new Types.ObjectId(ast.value); // ast value is always in string format
    }
    return null;
  }
}
