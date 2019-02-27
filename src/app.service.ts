import { Injectable } from '@nestjs/common';
import { ConfigService } from './config/config.service';
import { MongooseModule } from '@nestjs/mongoose';

@Injectable()
export class AppService {}
