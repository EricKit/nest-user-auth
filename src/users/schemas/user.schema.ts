import { Schema, model, Model, Document } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User } from '../../graphql.classes';

export interface UserDocument extends User, Document {
  _id: string;
  password: string;
  checkPassword(
    password: string,
    callback: (error?: Error, same?: boolean) => any,
  ): void;
}

export const UserSchema: Schema = new Schema(
  {
    email: {
      type: String,
      unique: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      unique: true,
      required: true,
    },
    permissions: {
      type: [String],
      required: true,
    },
  },
  {
    timestamps: true,
  },
);

// NOTE: Arrow functions are not used here as we do not want to use lexical scope for 'this'
UserSchema.pre<UserDocument>('save', function(next) {
  const user = this;

  // Make sure not to rehash the password if it is already hashed
  if (!user.isModified('password')) {
    return next();
  }

  // Generate a salt and use it to hash the user's password
  bcrypt.genSalt(10, (genSaltError, salt) => {
    if (genSaltError) {
      return next(genSaltError);
    }

    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});

// TODO: Redo the callback to match the bcrypt or make it nicer
UserSchema.methods.checkPassword = function(
  password: string,
  callback: (error?: Error, same?: boolean) => any,
) {
  const user = this;

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) {
      return callback(err);
    }
    callback(undefined, isMatch);
  });
};

export const UserModel: Model<UserDocument> = model<UserDocument>(
  'User',
  UserSchema,
);
