import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type RevokedTokensDocument = HydratedDocument<RevokedTokens>;

@Schema({ timestamps: true, collection: 'revoked_tokens' })
export class RevokedTokens {
  @Prop({ required: true })
  token: string;
}

export const RevokedTokensSchema = SchemaFactory.createForClass(RevokedTokens);
