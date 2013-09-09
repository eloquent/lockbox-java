/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.exception.DecryptionFailedException;
import co.lqnt.lockbox.key.PrivateKeyInterface;
import co.lqnt.lockbox.key.PublicKeyInterface;
import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.codec.Base64UriCodec;
import co.lqnt.lockbox.util.codec.CodecInterface;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

/**
 * The standard Lockbox bi-directional cipher.
 */
public class Cipher implements CipherInterface
{
    /**
     * Construct a new bi-directional cipher.
     */
    public Cipher()
    {
        CodecInterface base64UriCodec = new Base64UriCodec();
        AsymmetricBlockCipher rsaCipher = new OAEPEncoding(
            new RSAEngine(),
            new SHA1Digest()
        );
        BufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        Digest sha1Digest = new SHA1Digest();
        SecureRandom random = new SecureRandom();

        this.encryptionCipher = new EncryptionCipher(
            base64UriCodec,
            rsaCipher,
            aesCipher,
            sha1Digest,
            random
        );
        this.decryptionCipher = new DecryptionCipher(
            base64UriCodec,
            rsaCipher,
            aesCipher,
            sha1Digest
        );
    }

    /**
     * Construct a new bi-directional cipher.
     *
     * @param encryptionCipher The encryption cipher to use.
     * @param decryptionCipher The decryption cipher to use.
     */
    public Cipher(
        EncryptionCipherInterface encryptionCipher,
        DecryptionCipherInterface decryptionCipher
    ) {
        this.encryptionCipher = encryptionCipher;
        this.decryptionCipher = decryptionCipher;
    }

    /**
     * Get the encryption cipher.
     *
     * @return The encryption cipher.
     */
    public EncryptionCipherInterface encryptionCipher()
    {
        return this.encryptionCipher;
    }

    /**
     * Get the decryption cipher.
     *
     * @return The decryption cipher.
     */
    public DecryptionCipherInterface decryptionCipher()
    {
        return this.decryptionCipher;
    }

    /**
     * Encrypt a data packet.
     *
     * @param key  They key to encrypt with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public byte[] encrypt(final PublicKeyInterface key, final byte[] data)
    {
        return this.encryptionCipher().encrypt(key, data);
    }

    /**
     * Encrypt a data packet.
     *
     * @param key  They key to encrypt with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public String encrypt(final PublicKeyInterface key, final String data)
    {
        return this.encryptionCipher().encrypt(key, data);
    }

    /**
     * Encrypt a data packet.
     *
     * @param key  They key to encrypt with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public byte[] encrypt(final PrivateKeyInterface key, final byte[] data)
    {
        return this.encryptionCipher().encrypt(key, data);
    }

    /**
     * Encrypt a data packet.
     *
     * @param key  They key to encrypt with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public String encrypt(final PrivateKeyInterface key, final String data)
    {
        return this.encryptionCipher().encrypt(key, data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param key  They key to decrypt with.
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     * @throws DecryptionFailedException If the decryption failed.
     */
    public byte[] decrypt(final PrivateKeyInterface key, final byte[] data)
        throws DecryptionFailedException
    {
        return this.decryptionCipher().decrypt(key, data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param key  They key to decrypt with.
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     * @throws DecryptionFailedException If the decryption failed.
     */
    public String decrypt(final PrivateKeyInterface key, final String data)
        throws DecryptionFailedException
    {
        return this.decryptionCipher().decrypt(key, data);
    }

    private EncryptionCipherInterface encryptionCipher;
    private DecryptionCipherInterface decryptionCipher;
}
