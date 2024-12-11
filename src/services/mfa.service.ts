import { Injectable } from '@nestjs/common';
import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';

@Injectable()
export class MFAService {
  async generateSecret(username: string, issuer: string): Promise<{ secret: string; qrCode: string }> {
    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(username, issuer, secret);
    const qrCode = await QRCode.toDataURL(otpauthUrl);

    return {
      secret,
      qrCode,
    };
  }

  verifyToken(token: string, secret: string): boolean {
    return authenticator.verify({
      token,
      secret,
    });
  }
}
