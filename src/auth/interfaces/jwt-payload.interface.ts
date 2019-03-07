export interface JwtPayload {
  email: string;
  username: string;
  expiration?: Date;
}
