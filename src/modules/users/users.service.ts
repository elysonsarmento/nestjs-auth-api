import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { TokensService } from '../tokens/tokens.service';
import { User } from '@prisma/client';
import { RecoveryPasswordDto } from './dto/recovery-password.dto';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokensService: TokensService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<Omit<User, 'password'>> {
    const data = {
      ...createUserDto,
      password: await this.hashPassword(createUserDto.password),
    };

    try {
      const user = await this.prisma.user.create({ data });
      const token = await this.tokensService.create(user.id, 'CONFIRM');
      await this.sendConfirmationMail(user.email, token.id);

      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword;
    } catch (error) {
      this.logger.error('Erro ao criar usuário', error);
      throw new BadRequestException('Falha na criação do usuário');
    }
  }

  async changePassword(id: string, dto: ChangePasswordDto) {
    const { password, newPassword } = dto;
    const user = await this.findById(id);

    const passwordMatches = await this.validateHash(password, user.password);
    if (!passwordMatches) {
      throw new ForbiddenException('Senha atual incorreta');
    }

    const hashedPassword = await this.hashPassword(newPassword);

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data: { password: hashedPassword, refreshToken: null },
    });

    const { password: _, refreshToken, ...result } = updatedUser;
    return result;
  }

  async findById(id: string): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }
    return user;
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }
    return user;
  }

  async setRefreshToken(id: string, refreshToken: string | null) {
    const hashedToken = refreshToken
      ? await this.hashPassword(refreshToken)
      : null;

    await this.prisma.user.update({
      where: { id },
      data: { refreshToken: hashedToken },
    });
  }

  async findTokenById(tokenId: string, type: string) {
    const token = await this.tokensService.findOne(tokenId);
    if (!token || token.type !== type) {
      throw new NotFoundException('Token inválido ou não encontrado');
    }
    return token;
  }

  async requestRecovery(email: string) {
    const user = await this.findByEmail(email);
    const token = await this.tokensService.create(user.id, 'RECOVERY');

    await this.sendRecoveryMail(email, token.id);
    return { message: 'E-mail de recuperação enviado' };
  }

  async recoveryPassword(
    recoveryId: string,
    recoveryPasswordDto: RecoveryPasswordDto,
  ) {
    const { password, confirmPassword } = recoveryPasswordDto;

    if (password !== confirmPassword) {
      throw new BadRequestException('As senhas não coincidem');
    }

    const token = await this.findTokenById(recoveryId, 'RECOVERY');
    await this.updateUserPassword(token.userId, password);
    await this.tokensService.remove(recoveryId);

    return { message: 'Senha redefinida com sucesso' };
  }

  async confirm(confirmationId: string) {
    const token = await this.findTokenById(confirmationId, 'CONFIRM');
    await this.prisma.user.update({
      where: { id: token.userId },
      data: { confirmed: true },
    });
    await this.tokensService.remove(confirmationId);
    return { message: 'Usuário confirmado com sucesso' };
  }

  private async updateUserPassword(userId: string, newPassword: string) {
    const hashedPassword = await this.hashPassword(newPassword);
    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });
  }

  private async sendConfirmationMail(email: string, tokenId: string) {
    // Implementação do envio de e-mail de confirmação
  }

  private async sendRecoveryMail(email: string, tokenId: string) {
    // Implementação do envio de e-mail de recuperação
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async validateHash(content: string, hash: string) {
    return bcrypt.compare(content, hash);
  }
}