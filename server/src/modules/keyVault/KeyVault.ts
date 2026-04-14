import { Schema, Document, Types, model } from 'mongoose';

export interface IKeyVault extends Document
{
    _id:Types.ObjectId;
    orgId:Types.ObjectId;
    version:number;

     // ECDSA P-256
    encryptedECDSAPrivKey:Buffer;
    ecdsaPublicKey:string;
    ecdsaIv:Buffer;

    //ML-DSA-65
    encryptedDilithiumPrivKey:Buffer;
    dilithiumPublicKey:string;
    dilithiumIv:Buffer;
    // KDF
    salt:Buffer;
    //LIFE Cycle
    isActive:boolean;
    expiresAt:Date; 
    graceExpiresAt?:Date;
    createdAt: Date;
}

const keyVaultSchema = new Schema<IKeyVault>(
  {
    orgId: { type: Schema.Types.ObjectId, required: true, ref: 'Organization' },
    version: { type: Number, required: true },

    // ECDSA P-256
    encryptedECDSAPrivKey: { type: Buffer, required: true },
    ecdsaPublicKey: { type: String, required: true },
    ecdsaIv: { type: Buffer, required: true },

    // ML-DSA-65
    encryptedDilithiumPrivKey: { type: Buffer, required: true },
    dilithiumPublicKey: { type: String, required: true },
    dilithiumIv: { type: Buffer, required: true },

    // KDF
    salt: { type: Buffer, required: true },

    // Lifecycle
    isActive: { type: Boolean, required: true, default: false },
    expiresAt: { type: Date, required: true },
    graceExpiresAt: { type: Date },
    createdAt: { type: Date, required: true, default: () => new Date() },
  },
  {
    // No updatedAt — KeyVault records are effectively immutable after creation
    timestamps: false,
  }
);

keyVaultSchema.index({ orgId: 1, version: -1 });
keyVaultSchema.index({ orgId: 1, isActive: 1 });

export const KeyVault = model<IKeyVault>('KeyVault', keyVaultSchema);