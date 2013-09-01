/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.codec.Base64UriCodec;
import co.lqnt.lockbox.codec.CodecInterface;
import co.lqnt.lockbox.codec.exception.DecodingFailedException;
import co.lqnt.lockbox.exception.DecryptionFailedException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/**
 * The standard Lockbox decryption cipher.
 */
public class DecryptionCipher
{
    public DecryptionCipher()
    {
        this.sha1Digest = new SHA1Digest();
        this.rsaCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        this.aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.base64UriCodec = new Base64UriCodec();
    }

    public Digest sha1Digest()
    {
        return this.sha1Digest;
    }

    public AsymmetricBlockCipher rsaCipher()
    {
        return this.rsaCipher;
    }

    public BufferedBlockCipher aesCipher()
    {
        return this.aesCipher;
    }

    public CodecInterface base64UriCodec()
    {
        return this.base64UriCodec;
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
    public byte[] decrypt(final PrivateKey key, final byte[] data)
        throws DecryptionFailedException
    {
        AsymmetricKeyParameter keyParameter;
        try {
            keyParameter = PrivateKeyFactory.createKey(key.getEncoded());
        } catch (IOException e) {
            throw new DecryptionFailedException(new InvalidKeyException(e));
        }

        RSAPrivateCrtKeyParameters rsaKey;
        if (keyParameter instanceof RSAPrivateCrtKeyParameters) {
            rsaKey = (RSAPrivateCrtKeyParameters) keyParameter;
        } else {
            throw new DecryptionFailedException(new InvalidKeyException());
        }

        int keyLength = rsaKey.getModulus().bitLength() / 8;

        byte[] decodedData;
        try {
            decodedData = this.base64UriCodec().decode(data);
        } catch (DecodingFailedException e) {
            throw new DecryptionFailedException(e);
        }

        this.rsaCipher().init(false, keyParameter);

        byte[] keyAndIv;
        try {
            keyAndIv = this.rsaCipher().processBlock(
                Arrays.copyOfRange(decodedData, 0, keyLength),
                0,
                keyLength
            );
        } catch (InvalidCipherTextException e) {
            throw new DecryptionFailedException(e);
        }

        byte[] generatedKey = Arrays.copyOfRange(keyAndIv, 0, 32);

        byte[] iv;
        try {
            iv = Arrays.copyOfRange(keyAndIv, 32, keyAndIv.length);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new DecryptionFailedException(e);
        }

        byte[] hashAndData = this.decryptAes(
            generatedKey,
            iv,
            Arrays.copyOfRange(decodedData, keyLength, decodedData.length)
        );
        byte[] verificationHash = Arrays.copyOfRange(hashAndData, 0, 20);

        byte[] decrypted;
        try {
            decrypted = Arrays.copyOfRange(hashAndData, 20, hashAndData.length);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new DecryptionFailedException(e);
        }

        byte[] hash = new byte[20];
        this.sha1Digest().reset();
        this.sha1Digest().update(decrypted, 0, decrypted.length);
        this.sha1Digest().doFinal(hash, 0);

        if (!Arrays.equals(verificationHash, hash)) {
            throw new DecryptionFailedException();
        }

        return decrypted;
    }

    /**
     * Decrypt some data with AES and PKCS #7 padding.
     *
     * @param key  The key to use.
     * @param iv   The initialization vector to use.
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     * @throws DecryptionFailedException If the decryption failed.
     */
    protected byte[] decryptAes(
        final byte[] key,
        final byte[] iv,
        final byte[] data
    )
        throws DecryptionFailedException
    {
        CipherParameters parameters = new ParametersWithIV(
            new KeyParameter(key),
            iv
        );

        this.aesCipher().reset();
        this.aesCipher().init(false, parameters);

        int outputSize = this.aesCipher().getOutputSize(data.length);
        byte[] decrypted = new byte[outputSize];

        int length = this.aesCipher().processBytes(
            data,
            0,
            data.length,
            decrypted,
            0
        );

        try {
            length += this.aesCipher().doFinal(decrypted, length);
        } catch (InvalidCipherTextException e) {
            throw new DecryptionFailedException(e);
        }

        return Arrays.copyOfRange(decrypted, 0, length);
    }

    private Digest sha1Digest;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private CodecInterface base64UriCodec;
}
