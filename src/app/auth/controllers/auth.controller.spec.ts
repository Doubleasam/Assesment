import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AuthModule } from '../auth.module';
import { getModelToken } from '@nestjs/mongoose';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { UserDocument } from '../../../shared/models/user.model';
import { RevokedTokensDocument } from '../../../shared/models/revokedTokens.model';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';
import * as helper from '../../../shared/utils/helpers.utls';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let userModel: any;
  let revokedTokensModel: any;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [],
      providers: [
        {
          provide: getModelToken('User'),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            findByIdAndUpdate: jest.fn(),
            exists: jest.fn(),
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

    app = moduleFixture.createNestApplication();
    jwtService = moduleFixture.get<JwtService>(JwtService);
    userModel = moduleFixture.get(getModelToken('User'));
    revokedTokensModel = moduleFixture.get(getModelToken('RevokedTokens'));

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('/v1/auth/register (POST)', () => {
    it('should register a new user', async () => {
      const signupDto = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'Password123!',
      };

      jest
        .spyOn(crypto, 'randomBytes')
        .mockReturnValue(Buffer.from('randomBytes') as any);
      jest.spyOn(helper, 'encryptPassword').mockResolvedValue('hashedPassword');
      userModel.exists.mockResolvedValue(false);
      userModel.create.mockResolvedValue({
        _id: 'userId',
        name: signupDto.name,
        email: signupDto.email,
        refreshToken: 'randomBytes',
        password: 'hashedPassword',
      });
      jest
        .spyOn(jwtService, 'sign')
        .mockReturnValueOnce('accessToken')
        .mockReturnValueOnce('refreshToken');

      const response = await request(app.getHttpServer())
        .post('/v1/auth/register')
        .send(signupDto)
        .expect(201);

      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('authentication');
      expect(response.body.authentication.accessToken).toBe('accessToken');
      expect(response.body.authentication.refreshToken).toBe('refreshToken');
    });

    it('should throw an error if email already exists', async () => {
      const signupDto = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'Password123!',
      };

      userModel.exists.mockResolvedValue(true);

      await request(app.getHttpServer())
        .post('/v1/auth/register')
        .send(signupDto)
        .expect(400);
    });
  });

  describe('/v1/auth/login (POST)', () => {
    it('should log in a user', async () => {
      const loginDto = { email: 'test@example.com', password: 'Password123!' };
      const mockUser = {
        _id: 'userId',
        email: loginDto.email,
        password: 'hashedPassword',
      };

      userModel.findOne.mockResolvedValue(mockUser);
      jest
        .spyOn(helper, 'encryptPassword')
        .mockResolvedValue('$encryptedpassword');
      jest
        .spyOn(jwtService, 'sign')
        .mockReturnValueOnce('accessToken')
        .mockReturnValueOnce('refreshToken');

      const response = await request(app.getHttpServer())
        .post('/v1/auth/login')
        .send(loginDto)
        .expect(200);

      expect(response.body).toHaveProperty('user');
      expect(response.body.authentication.accessToken).toBe('accessToken');
      expect(response.body.authentication.refreshToken).toBe('refreshToken');
    });

    it('should return 401 if login credentials are invalid', async () => {
      const loginDto = {
        email: 'invalid@example.com',
        password: 'InvalidPassword',
      };
      userModel.findOne.mockResolvedValue(null);

      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .send(loginDto)
        .expect(401);
    });
  });

  describe('/v1/auth/profile (GET)', () => {
    it('should return the user profile', async () => {
      const mockUser = { _id: 'userId', email: 'test@example.com' };

      const response = await request(app.getHttpServer())
        .get('/v1/auth/profile')
        .set('Authorization', `Bearer validToken`)
        .expect(200);

      expect(response.body).toEqual(mockUser);
    });
  });

  describe('/v1/auth/logout (POST)', () => {
    it('should log out the user and revoke the token', async () => {
      await request(app.getHttpServer())
        .post('/v1/auth/logout')
        .set('Authorization', 'Bearer someToken')
        .expect(201);

      expect(revokedTokensModel.create).toHaveBeenCalledWith({
        token: 'someToken',
      });
    });
  });
});
