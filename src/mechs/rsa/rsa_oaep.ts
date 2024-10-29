import { Buffer } from "buffer";
import crypto from "crypto";
import * as core from "webcrypto-core";
import { RsaCrypto } from "./crypto";
import { RsaPrivateKey } from "./private_key";
import { RsaPublicKey } from "./public_key";
import { ShaCrypto } from "../sha/crypto";
import { setCryptoKey, getCryptoKey } from "../storage";

/**
 * Source code for decrypt, encrypt, mgf1 functions is from asmcrypto module
 * https://github.com/asmcrypto/asmcrypto.js/blob/master/src/rsa/pkcs1.ts
 *
 * This code can be removed after https://github.com/nodejs/help/issues/1726 fixed
 */

export class RsaOaepProvider extends core.RsaOaepProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await RsaCrypto.generateKey(
      {
        ...algorithm,
        name: this.name,
      },
      extractable,
      keyUsages);

      return {
        privateKey: setCryptoKey(keys.privateKey as RsaPrivateKey),
        publicKey: setCryptoKey(keys.publicKey as RsaPublicKey),
      };
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaPublicKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return RsaCrypto.encrypt(algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return RsaCrypto.decrypt(algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, getCryptoKey(key));
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return setCryptoKey(key);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    const internalKey = getCryptoKey(key);
    if (!(internalKey instanceof RsaPrivateKey || internalKey instanceof RsaPublicKey)) {
      throw new TypeError("key: Is not RSA CryptoKey");
    }
  }

  /**
   * RSA MGF1
   * @param algorithm Hash algorithm
   * @param seed
   * @param length
   */
  protected mgf1(algorithm: Algorithm, seed: Uint8Array, length = 0) {
    const hashSize = ShaCrypto.size(algorithm) >> 3;
    const mask = new Uint8Array(length);
    const counter = new Uint8Array(4);
    const chunks = Math.ceil(length / hashSize);
    for (let i = 0; i < chunks; i++) {
      counter[0] = i >>> 24;
      counter[1] = (i >>> 16) & 255;
      counter[2] = (i >>> 8) & 255;
      counter[3] = i & 255;

      const submask = mask.subarray(i * hashSize);

      let chunk = crypto.createHash(algorithm.name.replace("-", ""))
        .update(seed)
        .update(counter)
        .digest() as Uint8Array;
      if (chunk.length > submask.length) {
        chunk = chunk.subarray(0, submask.length);
      }

      submask.set(chunk);
    }

    return mask;
  }

}
