import * as bcrypt from 'bcryptjs';

export function isDevelopement(): boolean {
  return process.env.NODE_ENV?.startsWith('dev') ? true : false;
}

export function isProduction(): boolean {
  return process.env.NODE_ENV?.startsWith('prod') ? true : false;
}

export async function encryptPassword(password: string): Promise<string> {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  const hash = await bcrypt.hash(password, salt);
  return hash;
}

export async function comparePassword(
  passwordToCompare: string,
  password: string,
): Promise<boolean> {
  return await bcrypt.compare(password, passwordToCompare);
}
