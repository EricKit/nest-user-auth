import { Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { UserDocument } from './schemas/user.schema';
import { CreateUserInput } from '../graphql.classes';

@Injectable()
export class UsersService {
  constructor(@InjectModel('User') private userModel: Model<UserDocument>) {}

  isAdmin(permissions: string[]): boolean {
    return permissions.includes('admin');
  }

  async create(createUserInput: CreateUserInput) {
    const createdUser = new this.userModel(createUserInput);
    return await createdUser.save();
  }

  async findOneByEmail(email: string): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ email }).exec();
    return user;
  }

  async findOneByUsername(username: string): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ username }).exec();
    return user;
  }

  async getAllUsers(): Promise<UserDocument[]> {
    const users = await this.userModel.find().exec();
    return users;
  }
}
