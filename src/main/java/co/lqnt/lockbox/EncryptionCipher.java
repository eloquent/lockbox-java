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
import co.lqnt.lockbox.key.KeyInterface;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
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
public class EncryptionCipher
{
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
    }

    public CodecInterface base64UriCodec()
    {
        return this.base64UriCodec;
    }

    public AsymmetricBlockCipher rsaCipher()
    {
        return this.rsaCipher;
    }

    public BufferedBlockCipher aesCipher()
    {
        return this.aesCipher;
    }

    public Digest sha1Digest()
    {
        return this.sha1Digest;
    }

    public SecureRandom random()
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
    public byte[] encrypt(final KeyInterface key, final byte[] data)
        throws InvalidKeyException
    {
        byte[] generatedKey = new byte[32];
        byte[] iv = new byte[16];
        this.random().nextBytes(generatedKey);
        this.random().nextBytes(iv);

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

        return encrypted;
    }

    private CodecInterface base64UriCodec;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private Digest sha1Digest;
    private SecureRandom random;
}
