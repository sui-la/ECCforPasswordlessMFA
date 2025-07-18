// Crypto service for ECC operations using Web Crypto API
export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  privateKeyPem: string;
  publicKeyPem: string;
}

export interface SignatureResult {
  signature: string;
  publicKey: string;
}

class CryptoService {
  private algorithm = {
    name: 'ECDSA',
    namedCurve: 'P-256',
  };

  private exportFormat = 'spki';
  private extractable = true;

  /**
   * Generate ECC key pair
   */
  async generateKeyPair(): Promise<KeyPair> {
    try {
      // Generate key pair
      const keyPair = await window.crypto.subtle.generateKey(
        this.algorithm,
        this.extractable,
        ['sign', 'verify']
      );

      // Export keys to PEM format
      const publicKeyPem = await this.exportPublicKey(keyPair.publicKey);
      const privateKeyPem = await this.exportPrivateKey(keyPair.privateKey);

      return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        privateKeyPem,
        publicKeyPem,
      };
    } catch (error) {
      console.error('Error generating key pair:', error);
      throw new Error('Failed to generate key pair');
    }
  }

  /**
   * Import private key from PEM format
   */
      async importPrivateKey(privateKeyPem: string): Promise<CryptoKey> {
    try {
      const privateKeyData = this.pemToArrayBuffer(privateKeyPem, 'PRIVATE KEY');
      return await window.crypto.subtle.importKey(
        'pkcs8',
        privateKeyData,
        this.algorithm,
        this.extractable,
        ['sign']
      );
    } catch (error) {
      console.error('Error importing private key:', error);
      throw new Error('Failed to import private key');
    }
  }

  /**
   * Import public key from PEM format
   */
  async importPublicKey(publicKeyPem: string): Promise<CryptoKey> {
    try {
      const publicKeyData = this.pemToArrayBuffer(publicKeyPem, 'PUBLIC KEY');
      return await window.crypto.subtle.importKey(
        'spki',
        publicKeyData,
        this.algorithm,
        this.extractable,
        ['verify']
      );
    } catch (error) {
      console.error('Error importing public key:', error);
      throw new Error('Failed to import public key');
    }
  }

  /**
   * Sign data with private key
   */
  async sign(privateKey: CryptoKey, data: string | ArrayBuffer): Promise<string> {
    try {
      // If data is base64, decode it; otherwise, encode as UTF-8
      let dataBuffer: ArrayBuffer;
      if (typeof data === 'string') {
        // Try to detect if it's base64 (challenge nonces often are)
        if (/^[A-Za-z0-9+/=]+$/.test(data) && data.length % 4 === 0) {
          dataBuffer = this.base64ToArrayBuffer(data);
        } else {
          dataBuffer = this.stringToArrayBuffer(data);
        }
      } else {
        dataBuffer = data;
      }
  
      const algorithm = { name: 'ECDSA', hash: { name: 'SHA-256' } };
      console.log('Signing with algorithm:', algorithm, 'Data length:', dataBuffer.byteLength);
  
      const signature = await window.crypto.subtle.sign(
        algorithm,
        privateKey,
        dataBuffer
      );
      return this.arrayBufferToBase64(signature);
    } catch (error) {
      console.error('Error signing data:', error);
      throw new Error('Failed to sign data');
    }
  }

  /**
   * Verify signature with public key
   */
  async verify(
    publicKey: CryptoKey,
    signature: string,
    data: string | ArrayBuffer
  ): Promise<boolean> {
    try {
      const dataBuffer = typeof data === 'string' ? this.stringToArrayBuffer(data) : data;
      const signatureBuffer = this.base64ToArrayBuffer(signature);
      return await window.crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } }, // FIXED: include hash
        publicKey,
        signatureBuffer,
        dataBuffer
      );
    } catch (error) {
      console.error('Error verifying signature:', error);
      return false;
    }
  }

  /**
   * Generate cryptographically secure random bytes
   */
  generateRandomBytes(length: number): string {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return this.arrayBufferToBase64(array);
  }

  /**
   * Export public key to PEM format
   */
  private async exportPublicKey(publicKey: CryptoKey): Promise<string> {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    const base64 = this.arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----`;
  }

  /**
   * Export private key to PEM format
   */
  private async exportPrivateKey(privateKey: CryptoKey): Promise<string> {
    const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    const base64 = this.arrayBufferToBase64(exported);
    return `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----`;
  }

  /**
   * Convert PEM to ArrayBuffer
   */
  private pemToArrayBuffer(pem: string, keyType: string): ArrayBuffer {
    const base64 = pem
      .replace(`-----BEGIN ${keyType}-----`, '')
      .replace(`-----END ${keyType}-----`, '')
      .replace(/\s/g, '');
    return this.base64ToArrayBuffer(base64);
  }

  /**
   * Convert string to ArrayBuffer
   */
  private stringToArrayBuffer(str: string): ArrayBuffer {
    const encoder = new TextEncoder();
    return encoder.encode(str);
  }

  /**
   * Convert ArrayBuffer to base64 string
   */
  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string to ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Hash data using SHA-256
   */
  async hash(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBuffer);
    return this.arrayBufferToBase64(hashBuffer);
  }

  /**
   * Generate challenge nonce
   */
  generateNonce(): string {
    return this.generateRandomBytes(32);
  }

  /**
   * Sign challenge for authentication
   */
  async signChallenge(privateKeyPem: string, nonce: string): Promise<string> {
    try {
      const privateKey = await this.importPrivateKey(privateKeyPem);
      return await this.sign(privateKey, nonce);
    } catch (error) {
      console.error('Error signing challenge:', error);
      throw new Error('Failed to sign challenge');
    }
  }

  /**
   * Verify challenge signature
   */
  async verifyChallenge(
    publicKeyPem: string,
    signature: string,
    nonce: string
  ): Promise<boolean> {
    try {
      const publicKey = await this.importPublicKey(publicKeyPem);
      return await this.verify(publicKey, signature, nonce);
    } catch (error) {
      console.error('Error verifying challenge:', error);
      return false;
    }
  }
}

export const cryptoService = new CryptoService(); 