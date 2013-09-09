/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.util.codec.Base64UriCodec;
import co.lqnt.lockbox.util.codec.CodecInterface;
import co.lqnt.lockbox.key.PrivateKeyInterface;
import co.lqnt.lockbox.key.PublicKeyInterface;
import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.SecureRandomInterface;
import java.nio.charset.Charset;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * The standard Lockbox encryption cipher.
 */
public class EncryptionCipher implements EncryptionCipherInterface
{
    /**
     * Construct a new encryption cipher.
     */
    public EncryptionCipher()
    {
        this.base64UriCodec = new Base64UriCodec();
        this.rsaCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        this.aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.sha1Digest = new SHA1Digest();
        this.random = new SecureRandom();
        this.asciiCharset = Charset.forName("US-ASCII");
    }

    /**
     * Construct a new encryption cipher.
     *
     * @param base64UriCodec The URI-safe Base64 codec to use.
     * @param rsaCipher      The Bouncy Castle RSA cipher to use.
     * @param aesCipher      The Bouncy Castle AES cipher to use.
     * @param sha1Digest     The Bouncy Castle SHA-1 message digest to use.
     * @param random         The secure random generator to use.
     */
    public EncryptionCipher(
        CodecInterface base64UriCodec,
        AsymmetricBlockCipher rsaCipher,
        BufferedBlockCipher aesCipher,
        Digest sha1Digest,
        SecureRandomInterface random
    ) {
        this.base64UriCodec = base64UriCodec;
        this.rsaCipher = rsaCipher;
        this.aesCipher = aesCipher;
        this.sha1Digest = sha1Digest;
        this.random = random;
        this.asciiCharset = Charset.forName("US-ASCII");
    }

    /**
     * Get the URI-safe Base64 codec.
     *
     * @return The URI-safe Base64 codec.
     */
    public CodecInterface base64UriCodec()
    {
        return this.base64UriCodec;
    }

    /**
     * Get the Bouncy Castle RSA cipher.
     *
     * @return The Bouncy Castle RSA cipher.
     */
    public AsymmetricBlockCipher rsaCipher()
    {
        return this.rsaCipher;
    }

    /**
     * Get the Bouncy Castle AES cipher.
     *
     * @return The Bouncy Castle AES cipher.
     */
    public BufferedBlockCipher aesCipher()
    {
        return this.aesCipher;
    }

    /**
     * Get the Bouncy Castle SHA-1 message digest.
     *
     * @return The Bouncy Castle SHA-1 message digest.
     */
    public Digest sha1Digest()
    {
        return this.sha1Digest;
    }

    /**
     * Get the secure random generator.
     *
     * @return The secure random generator.
     */
    public SecureRandomInterface random()
    {
        return this.random;
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
        byte[] generatedKey = this.random().generate(32);
        byte[] iv = this.random().generate(16);

        byte[] keyAndIv = new byte[48];
        System.arraycopy(generatedKey, 0, keyAndIv, 0, 32);
        System.arraycopy(iv, 0, keyAndIv, 32, 16);

        this.rsaCipher().init(true, key.bcKeyParameters());

        byte[] encryptedKeyAndIv;
        try {
            encryptedKeyAndIv = this.rsaCipher().processBlock(keyAndIv, 0, 48);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        byte[] hash = new byte[20];
        this.sha1Digest().reset();
        this.sha1Digest().update(data, 0, data.length);
        this.sha1Digest().doFinal(hash, 0);

        byte[] hashAndData = new byte[20 + data.length];
        System.arraycopy(hash, 0, hashAndData, 0, 20);
        System.arraycopy(data, 0, hashAndData, 20, data.length);

        byte[] encryptedData = this.encryptAes(generatedKey, iv, hashAndData);

        int encryptedSize = encryptedKeyAndIv.length + encryptedData.length;
        byte[] encrypted = new byte[encryptedSize];
        System.arraycopy(
            encryptedKeyAndIv,
            0,
            encrypted,
            0,
            encryptedKeyAndIv.length
        );
        System.arraycopy(
            encryptedData,
            0,
            encrypted,
            encryptedKeyAndIv.length,
            encryptedData.length
        );

        return this.base64UriCodec().encode(encrypted);
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
        return new String(
            this.encrypt(key, data.getBytes(this.asciiCharset)),
            this.asciiCharset
        );
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
        return this.encrypt(key.publicKey(), data);
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
        return new String(
            this.encrypt(key, data.getBytes(this.asciiCharset)),
            this.asciiCharset
        );
    }

    /**
     * Encrypt some data with AES and PKCS #7 padding.
     *
     * @param key  The key to use.
     * @param iv   The initialization vector to use.
     * @param data The data to encrypt.
     *
     * @return The decrypted data.
     */
    protected byte[] encryptAes(
        final byte[] key,
        final byte[] iv,
        final byte[] data
    ) {
        CipherParameters parameters = new ParametersWithIV(
            new KeyParameter(key),
            iv
        );

        this.aesCipher().reset();
        this.aesCipher().init(true, parameters);

        int outputSize = this.aesCipher().getOutputSize(data.length);
        byte[] encrypted = new byte[outputSize];

        int length = this.aesCipher().processBytes(
            data,
            0,
            data.length,
            encrypted,
            0
        );

        try {
            length += this.aesCipher().doFinal(encrypted, length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        } catch (DataLengthException e) {
            throw new RuntimeException(e);
        }

        return Arrays.copyOfRange(encrypted, 0, length);
    }

    private CodecInterface base64UriCodec;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private Digest sha1Digest;
    private SecureRandomInterface random;
    private Charset asciiCharset;
}
