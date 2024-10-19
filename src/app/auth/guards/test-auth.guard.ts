import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { IncomingMessage } from 'http';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../../shared/decorators/public.decorator';
import { User, UserDocument } from '../../../shared/models/user.model';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import {
  RevokedTokens,
  RevokedTokensDocument,
} from '../../../shared/models/revokedTokens.model';
import { encryptPassword } from '../../../shared/utils/helpers.utls';

@Injectable()
export class TestAuthGuard implements CanActivate {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    @InjectModel(RevokedTokens.name)
    private readonly revokedTokensModel: Model<RevokedTokensDocument>,
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get isPublic decorator
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Allow access if isPublic is true
    if (isPublic) {
      return true;
    }

    const request = this.getRequest<IncomingMessage & { user?: UserDocument }>(
      context,
    );

    try {
      // get token
      const token = this.getToken(request);

      const revokedToken = await this.revokedTokensModel.findOne({ token });

      if (revokedToken) {
        throw new UnauthorizedException();
      }

      // verify token
      // const payload = await this.jwtService.verifyAsync(token, {
      //   secret: this.configService.get<string>('JWT_SECRET'),
      // });

      // get user id
      // const userId = payload.id;

      // get user by id
      // const user: UserDocument | null = await this.userModel.findOne({
      //   _id: userId,
      // });

      // return exception if unable to get user
      // if (!user) throw Error();

      request.user = {
        _id: new Types.ObjectId('671238a6eb6d929e2f6c93fe'),
        name: 'johnDoe',
        password: await encryptPassword('password123-'),
        refreshToken: await encryptPassword('refresh_token'),
      } as UserDocument;

      return true;
    } catch (e) {
      throw new UnauthorizedException();
    }
  }
  protected getRequest<T>(context: ExecutionContext): T {
    return context.switchToHttp().getRequest();
  }
  protected getToken(
    request: IncomingMessage & { user?: UserDocument | undefined },
  ): string {
    // get auth header
    const authorization = request.headers['authorization'];

    // check if auth header is valid
    if (
      !authorization ||
      authorization.trim() === '' ||
      Array.isArray(authorization)
    ) {
      throw new UnauthorizedException();
    }

    // get token from header
    const [_, token] = authorization.split(' ');
    return token;
  }
}
