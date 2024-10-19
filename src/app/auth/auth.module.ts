import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../../shared/models/user.model';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './guards/auth.guard';
import {
  RevokedTokens,
  RevokedTokensSchema,
} from '../../shared/models/revokedTokens.model';
import { ConfigService } from '@nestjs/config';
import { TestAuthGuard } from './guards/test-auth.guard';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RevokedTokens.name, schema: RevokedTokensSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: APP_GUARD,
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        if (configService.get('NODE_ENV') === 'test') {
          return TestAuthGuard;
        }
        return AuthGuard;
      },
    },
  ],
})
export class AuthModule {}
