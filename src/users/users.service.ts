import { Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { UserDocument } from './schemas/user.schema';
import { CreateUserInput, UpdateUserInput } from '../graphql.classes';
import { randomBytes } from 'crypto';
import { createTransport, SendMailOptions } from 'nodemailer';
import {
  EMAIL_SERVICE,
  EMAIL_USERNAME,
  EMAIL_PASSWORD,
  EMAIL_FROM,
} from '../../secrets';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
  ) {}

  isAdmin(permissions: string[]): boolean {
    return permissions.includes('admin');
  }

  async addPermission(
    permission: string,
    username: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (!user) return undefined;
    if (user.permissions.includes(permission)) return user;
    user.permissions.push(permission);
    await user.save();
    return user;
  }

  async removePermission(
    permission: string,
    username: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (!user) return undefined;
    user.permissions = user.permissions.filter(
      userPermission => userPermission !== permission,
    );
    await user.save();
    return user;
  }

  async update(
    username: string,
    fieldsToUpdate: UpdateUserInput,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);

    if (!user) return undefined;

    if (fieldsToUpdate.username) user.username = fieldsToUpdate.username;
    if (fieldsToUpdate.email) user.email = fieldsToUpdate.email;
    if (fieldsToUpdate.password) user.password = fieldsToUpdate.password;

    // Save will hash the password
    await user.save();
    return user;
  }

  async forgotPassword(email: string): Promise<boolean> {
    const user = await this.findOneByEmail(email);
    if (!user) return false;
    const token = randomBytes(32).toString('hex');

    // One day
    const expiration = new Date(Date().valueOf() + 24 * 60 * 60 * 1000);

    const transporter = createTransport({
      service: EMAIL_SERVICE,
      auth: {
        user: EMAIL_USERNAME,
        pass: EMAIL_PASSWORD,
      },
    });

    const mailOptions: SendMailOptions = {
      from: EMAIL_FROM,
      to: email,
      subject: `Reset Password`,
      text: `${user.username},
      Replace this with a website that can pass the token:
      ${token}`,
    };

    return new Promise(resolve => {
      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          resolve(false);
          return;
        }

        user.passwordReset = {
          token,
          expiration,
        };

        user.save().then(() => resolve(true), () => resolve(false));
      });
    });
  }

  async resetPassword(
    username: string,
    code: string,
    password: string,
  ): Promise<UserDocument | undefined> {
    const user = await this.findOneByUsername(username);
    if (user && user.passwordReset) {
      if (user.passwordReset.token === code) {
        user.password = password;
        user.passwordReset = undefined;
        await user.save();
        return user;
      }
    }
    return undefined;
  }

  async create(createUserInput: CreateUserInput) {
    const createdUser = new this.userModel(createUserInput);
    createdUser.lowercaseUsername = createdUser.username.toLowerCase();
    createdUser.lowercaseEmail = createdUser.email.toLowerCase();
    const user = await createdUser.save();
    return user;
  }

  async findOneByEmail(email: string): Promise<UserDocument | undefined> {
    const user = await this.userModel
      .findOne({ lowercaseEmail: email.toLowerCase() })
      .exec();
    if (user) return user;
    return undefined;
  }

  async findOneByUsername(username: string): Promise<UserDocument | undefined> {
    const user = await this.userModel
      .findOne({ lowercaseUsername: username.toLowerCase() })
      .exec();
    if (user) return user;
    return undefined;
  }

  async getAllUsers(): Promise<UserDocument[]> {
    const users = await this.userModel.find().exec();
    return users;
  }
}
