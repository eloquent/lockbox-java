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
import co.lqnt.lockbox.util.codec.exception.DecodingFailedException;
import co.lqnt.lockbox.exception.DecryptionFailedException;
import co.lqnt.lockbox.key.PrivateKeyInterface;
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
 * The standard Lockbox decryption cipher.
 */
public class DecryptionCipher implements DecryptionCipherInterface
{
    /**
     * Construct a new decryption cipher.
     */
    public DecryptionCipher()
    {
        this.base64UriCodec = new Base64UriCodec();
        this.rsaCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        this.aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.sha1Digest = new SHA1Digest();
    }

    /**
     * Construct a new decryption cipher.
     *
     * @param base64UriCodec The URI-safe Base64 codec to use.
     * @param rsaCipher      The Bouncy Castle RSA cipher to use.
     * @param aesCipher      The Bouncy Castle AES cipher to use.
     * @param sha1Digest     The Bouncy Castle SHA-1 message digest to use.
     */
    public DecryptionCipher(
        CodecInterface base64UriCodec,
        AsymmetricBlockCipher rsaCipher,
        BufferedBlockCipher aesCipher,
        Digest sha1Digest
    ) {
        this.base64UriCodec = base64UriCodec;
        this.rsaCipher = rsaCipher;
        this.aesCipher = aesCipher;
        this.sha1Digest = sha1Digest;
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
        int keySize = key.size() / 8;

        byte[] decodedData;
        try {
            decodedData = this.base64UriCodec().decode(data);
        } catch (DecodingFailedException e) {
            throw new DecryptionFailedException(e);
        }

        this.rsaCipher().init(false, key.bcKeyParameters());

        byte[] keyAndIv;
        try {
            keyAndIv = this.rsaCipher().processBlock(
                Arrays.copyOfRange(decodedData, 0, keySize),
                0,
                keySize
            );
        } catch (InvalidCipherTextException e) {
            throw new DecryptionFailedException(e);
        }

        byte[] generatedKey = Arrays.copyOfRange(keyAndIv, 0, 32);

        byte[] iv;
        try {
            iv = Arrays.copyOfRange(keyAndIv, 32, keyAndIv.length);
        } catch (IllegalArgumentException e) {
            throw new DecryptionFailedException(e);
        }

        byte[] hashAndData = this.decryptAes(
            generatedKey,
            iv,
            Arrays.copyOfRange(decodedData, keySize, decodedData.length)
        );
        byte[] verificationHash = Arrays.copyOfRange(hashAndData, 0, 20);

        byte[] decrypted;
        try {
            decrypted = Arrays.copyOfRange(hashAndData, 20, hashAndData.length);
        } catch (IllegalArgumentException e) {
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

        try {
            this.aesCipher().init(false, parameters);
        } catch (IllegalArgumentException e) {
            throw new DecryptionFailedException(e);
        }

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
        } catch (DataLengthException e) {
            throw new DecryptionFailedException(e);
        }

        return Arrays.copyOfRange(decrypted, 0, length);
    }

    private CodecInterface base64UriCodec;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private Digest sha1Digest;
}
