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

/**
 * The standard Lockbox bi-directional cipher, with a bound key.
 */
public class BoundCipher implements BoundCipherInterface
{
    /**
     * Construct a new bound bi-directional cipher.
     *
     * @param privateKey The private key to use.
     */
    public BoundCipher(final PrivateKeyInterface privateKey)
    {
        this(privateKey, privateKey.publicKey());
    }

    /**
     * Construct a new bound bi-directional cipher.
     *
     * @param privateKey The private key to use.
     * @param publicKey  The public key to use.
     */
    public BoundCipher(
        final PrivateKeyInterface privateKey,
        final PublicKeyInterface publicKey
    ) {
        this(
            privateKey,
            publicKey,
            new EncryptionCipher(),
            new DecryptionCipher()
        );
    }

    /**
     * Construct a new bound bi-directional cipher.
     *
     * @param privateKey       The private key to use.
     * @param publicKey        The public key to use.
     * @param encryptionCipher The encryption cipher to use.
     * @param decryptionCipher The decryption cipher to use.
     */
    public BoundCipher(
        final PrivateKeyInterface privateKey,
        final PublicKeyInterface publicKey,
        final EncryptionCipherInterface encryptionCipher,
        final DecryptionCipherInterface decryptionCipher
    ) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.encryptionCipher = encryptionCipher;
        this.decryptionCipher = decryptionCipher;
    }

    /**
     * Get the private key.
     *
     * @return The private key.
     */
    public PrivateKeyInterface privateKey()
    {
        return this.privateKey;
    }

    /**
     * Get the public key.
     *
     * @return The public key.
     */
    public PublicKeyInterface publicKey()
    {
        return this.publicKey;
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
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public byte[] encrypt(final byte[] data)
    {
        return this.encryptionCipher().encrypt(this.publicKey(), data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     */
    public byte[] decrypt(final byte[] data) throws DecryptionFailedException
    {
        return this.decryptionCipher().decrypt(this.privateKey(), data);
    }

    private PrivateKeyInterface privateKey;
    private PublicKeyInterface publicKey;
    private EncryptionCipherInterface encryptionCipher;
    private DecryptionCipherInterface decryptionCipher;
}
