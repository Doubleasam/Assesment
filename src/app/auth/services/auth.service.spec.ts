import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getModelToken } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserDocument } from '../../../shared/models/user.model';
import { RevokedTokensDocument } from '../../../shared/models/revokedTokens.model';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { SignupDto, LoginDto } from '../dto/auth.dto';
import { Request } from 'express';
import * as helper from '../../../shared/utils/helpers.utls';

describe('AuthService', () => {
  let authService: AuthService;
  let userModel: any;
  let revokedTokensModel: any;
  let jwtService: JwtService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getModelToken('User'),
          useValue: {
            findByIdAndUpdate: jest.fn(),
            exists: jest.fn(),
            create: jest.fn(),
            findOne: jest.fn(),
          },
        },
        {
          provide: getModelToken('RevokedTokens'),
          useValue: {
            create: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userModel = module.get(getModelToken('User'));
    revokedTokensModel = module.get(getModelToken('RevokedTokens'));
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
  });

  describe('generateTokens', () => {
    it('should generate and return tokens', async () => {
      const mockUser = {
        _id: 'userId',
        email: 'test@example.com',
        refreshToken: '',
      };
      const mockAccessToken = 'accessToken';
      const mockRefreshToken = 'refreshToken';

      userModel.findByIdAndUpdate.mockResolvedValueOnce({
        ...mockUser,
        refreshToken: 'newRefreshToken',
      });

      jest
        .spyOn(jwtService, 'sign')
        // jwtService.sign
        .mockReturnValueOnce(mockAccessToken)
        .mockReturnValueOnce(mockRefreshToken);

      jest
        .spyOn(configService, 'get')
        // configService.get
        .mockReturnValueOnce('refreshSecret');

      const result = await authService.generateTokens(
        mockUser as unknown as UserDocument,
      );

      expect(userModel.findByIdAndUpdate).toHaveBeenCalledWith(
        mockUser._id,
        expect.any(Object),
        { new: true },
      );
      expect(jwtService.sign).toHaveBeenNthCalledWith(1, {
        email: mockUser.email,
        id: mockUser._id,
      });
      expect(jwtService.sign).toHaveBeenNthCalledWith(
        2,
        { refreshToken: 'newRefreshToken' },
        { secret: 'refreshSecret', expiresIn: '7d' },
      );
      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
    });
  });

  describe('signup', () => {
    it('should throw BadRequestException if email already exists', async () => {
      const mockSignupDto: SignupDto = {
        name: 'Test',
        email: 'test@example.com',
        password: 'password',
      };
      userModel.exists.mockResolvedValueOnce(true);

      await expect(authService.signup(mockSignupDto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should create a new user and return tokens', async () => {
      const mockSignupDto: SignupDto = {
        name: 'Test',
        email: 'test@example.com',
        password: 'password',
      };
      const mockUser = {
        _id: 'userId',
        email: 'test@example.com',
        refreshToken: '',
        password: 'hashedPassword',
      };
      const mockTokens = {
        accessToken: 'accessToken',
        refreshToken: 'refreshToken',
      };

      userModel.exists.mockResolvedValueOnce(false);
      jest
        .spyOn(crypto, 'randomBytes')
        .mockReturnValueOnce(Buffer.from('randomBytes') as any);
      jest
        .spyOn(helper, 'encryptPassword')
        .mockResolvedValueOnce('hashedPassword');
      userModel.create.mockResolvedValueOnce(mockUser);
      jest
        .spyOn(authService, 'generateTokens')
        .mockResolvedValueOnce(mockTokens);

      const result = await authService.signup(mockSignupDto);

      expect(userModel.exists).toHaveBeenCalledWith({
        email: mockSignupDto.email,
      });
      expect(userModel.create).toHaveBeenCalledWith(expect.any(Object));
      expect(authService.generateTokens).toHaveBeenCalledWith(mockUser);
      expect(result).toEqual({ user: mockUser, authentication: mockTokens });
    });
  });

  describe('login', () => {
    it('should throw UnauthorizedException if email does not exist', async () => {
      const mockLoginDto: LoginDto = {
        email: 'test@example.com',
        password: 'password',
      };
      userModel.findOne.mockResolvedValueOnce(null);

      await expect(authService.login(mockLoginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException if password is incorrect', async () => {
      const mockLoginDto: LoginDto = {
        email: 'test@example.com',
        password: 'password',
      };
      const mockUser = { password: 'hashedPassword' };

      userModel.findOne.mockResolvedValueOnce(mockUser);
      jest.spyOn(helper, 'comparePassword').mockResolvedValueOnce(false);

      await expect(authService.login(mockLoginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should return user and tokens on successful login', async () => {
      const mockLoginDto: LoginDto = {
        email: 'test@example.com',
        password: 'password',
      };
      const mockUser = {
        _id: 'userId',
        email: 'test@example.com',
        password: 'hashedPassword',
      };
      const mockTokens = {
        accessToken: 'accessToken',
        refreshToken: 'refreshToken',
      };

      userModel.findOne.mockResolvedValueOnce(mockUser);
      jest.spyOn(helper, 'comparePassword').mockResolvedValueOnce(true);
      jest
        .spyOn(authService, 'generateTokens')
        .mockResolvedValueOnce(mockTokens);

      const result = await authService.login(mockLoginDto);

      expect(userModel.findOne).toHaveBeenCalledWith({
        email: mockLoginDto.email,
      });
      expect(helper.comparePassword).toHaveBeenCalledWith(
        mockUser.password,
        mockLoginDto.password,
      );
      expect(authService.generateTokens).toHaveBeenCalledWith(mockUser);
      expect(result).toEqual({ user: mockUser, authentication: mockTokens });
    });
  });

  describe('logout', () => {
    it('should revoke the token', async () => {
      const mockRequest = {
        headers: { authorization: 'Bearer someToken' },
      } as Request;

      await authService.logout(mockRequest);

      expect(revokedTokensModel.create).toHaveBeenCalledWith({
        token: 'someToken',
      });
    });
  });
});
