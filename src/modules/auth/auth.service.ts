import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { UsersService } from '../users/users.service';
import { AuthLoginDto } from './dto/auth-login.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async login(authLoginDto: AuthLoginDto) {
    const user = await this.validateUser(authLoginDto);

    const refreshToken = this.jwtService.sign({ userId: user.id });
    await this.usersService.setRefreshToken(user.id, refreshToken);

    const accessToken = this.generateAccessToken(user);

    return {
      refreshToken,
      accessToken,
    };
  }

  async logout(id: string) {
    const user = await this.usersService.findById(id);
    if (!user) throw new NotFoundException('User not found');
    await this.usersService.setRefreshToken(id, null);

    return user;
  }

  private async validateUser(authLoginDto: AuthLoginDto): Promise<User> {
    const { email, password } = authLoginDto;
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const isPasswordValid = await this.usersService.validateHash(
      password,
      user.password,
    );
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid credentials');

    return user;
  }

  async updateAccessToken(refreshToken: string) {
    const data = this.jwtService.decode(refreshToken) as { userId: string };
    if (!data || !data.userId)
      throw new NotFoundException('Invalid refresh token');

    const user = await this.usersService.findById(data.userId);
    if (!user || !user.refreshToken)
      throw new BadRequestException('Invalid refresh token');

    const isValidRefreshToken = await this.usersService.validateHash(
      refreshToken,
      user.refreshToken,
    );
    if (!isValidRefreshToken)
      throw new UnauthorizedException('Invalid refresh token');

    const accessToken = this.generateAccessToken(user);

    return { accessToken };
  }

  private generateAccessToken(user: User): string {
    const payload = {
      userId: user.id,
      username: user.username,
      email: user.email,
    };
    return this.jwtService.sign(payload, { expiresIn: '10m' });
  }

  async validateRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<User> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    const isValidRefreshToken = await this.usersService.validateHash(
      refreshToken,
      user.refreshToken,
    );
    if (!isValidRefreshToken)
      throw new UnauthorizedException('Invalid refresh token');

    return user;
  }
}
