import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { User, UserDocument } from '../../../shared/models/user.model';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, FilterQuery } from 'mongoose';
import * as crypto from 'crypto';
import {
  comparePassword,
  encryptPassword,
} from '../../../shared/utils/helpers.utls';
import { LoginDto, SignupDto } from '../dto/auth.dto';
import {
  RevokedTokens,
  RevokedTokensDocument,
} from '../../../shared/models/revokedTokens.model';
import { Request } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    @InjectModel(RevokedTokens.name)
    private readonly revokedTokensModel: Model<RevokedTokensDocument>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async generateTokens(user: UserDocument) {
    // update user refresh token
    user = await this.userModel.findByIdAndUpdate(
      user._id,
      {
        refreshToken: crypto.randomBytes(32).toString('hex'),
      },
      { new: true },
    );

    // Generte access token
    const accessToken = this.jwtService.sign({
      email: user.email,
      id: user._id,
    });

    // Generate refresh token
    const refreshToken = this.jwtService.sign(
      { refreshToken: user.refreshToken },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );

    return {
      accessToken,
      refreshToken,
    };
  }

  async userAlreadyExist(
    user: FilterQuery<UserDocument>,
    callback: CallableFunction,
  ): Promise<void> {
    const exists = await this.userModel.exists(user);

    if (exists) {
      callback();
    }
  }

  async signup(data: SignupDto) {
    // check if mail exist
    await this.userAlreadyExist({ email: data.email }, function () {
      throw new BadRequestException(
        'User with email already exist in our record.',
      );
    });

    // Encrypt the password before saving the user
    const hashedPassword = await encryptPassword(data.password);
    const createdUser = await this.userModel.create({
      name: data.name,
      email: data.email,
      refreshToken: crypto.randomBytes(32).toString('hex'),
      password: hashedPassword,
    });

    // Generate access token and refresh token
    const tokens = await this.generateTokens(createdUser);

    return { user: createdUser, authentication: tokens };
  }

  async login({ email, password }: LoginDto): Promise<{
    user: UserDocument;
    authentication: { accessToken: string; refreshToken: string };
  }> {
    // Get user by email
    const user = await this.userModel.findOne({ email });

    // Return 401 if user does not exist
    if (!user) {
      throw new UnauthorizedException('Email or password is incorrect');
    }

    // Verify password
    const isPasswordValid = await comparePassword(user.password, password);

    // throw 401 if password does not match
    if (!isPasswordValid) {
      throw new UnauthorizedException('Email or password is incorrect');
    }

    return {
      user,
      authentication: await this.generateTokens(user),
    };
  }

  profile(user: UserDocument) {
    return user;
  }

  async logout(req: Request) {
    // get auth header
    const authorization = req.headers['authorization'];

    // get token from header
    const [, token] = authorization.split(' ');

    await this.revokedTokensModel.create({ token });
  }
}
