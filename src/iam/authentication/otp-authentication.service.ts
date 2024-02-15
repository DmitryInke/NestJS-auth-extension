import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { authenticator } from 'otplib';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class OtpAuthenticationService {
  constructor(
    private readonly configServce: ConfigService,
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
  ) {}

  async generateSecret(email: string) {
    const secret = authenticator.generateSecret();
    const appName = this.configServce.getOrThrow('TFA_APP_NAME');
    const uri = authenticator.keyuri(email, appName, secret);
    return {
      uri,
      secret,
    };
  }
  verifyCode(code: string, secret: string) {
    return authenticator.verify({
      token: code,
      secret,
    });
  }

  async enableTfaForUser(email: string, secret: string) {
    const { id } = await this.usersRepository.findOneOrFail({
      where: { email },
      select: { id: true },
    });
    await this.usersRepository.update(
      { id },
      { tfaSecret: secret, isTfaEnabled: true },
    );
  }
}
