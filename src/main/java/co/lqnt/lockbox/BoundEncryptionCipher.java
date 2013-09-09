/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.key.PrivateKeyInterface;
import co.lqnt.lockbox.key.PublicKeyInterface;

/**
 * The standard Lockbox encryption cipher, with a bound key.
 */
public class BoundEncryptionCipher implements BoundEncryptionCipherInterface
{
    /**
     * Construct a new bound encryption cipher.
     *
     * @param key The key to use.
     */
    public BoundEncryptionCipher(final PublicKeyInterface key)
    {
        this(key, new EncryptionCipher());
    }

    /**
     * Construct a new bound encryption cipher.
     *
     * @param key The key to use.
     */
    public BoundEncryptionCipher(final PrivateKeyInterface key)
    {
        this(key.publicKey(), new EncryptionCipher());
    }

    /**
     * Construct a new bound encryption cipher.
     *
     * @param key    The key to use.
     * @param cipher The cipher to use.
     */
    public BoundEncryptionCipher(
        final PublicKeyInterface key,
        final EncryptionCipherInterface cipher
    ) {
        this.key = key;
        this.cipher = cipher;
    }

    /**
     * Get the key.
     *
     * @return The key.
     */
    public PublicKeyInterface key()
    {
        return this.key;
    }

    /**
     * Get the cipher.
     *
     * @return The cipher.
     */
    public EncryptionCipherInterface cipher()
    {
        return this.cipher;
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
        return this.cipher().encrypt(this.key(), data);
    }

    /**
     * Encrypt a data packet.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public String encrypt(final String data)
    {
        return this.cipher().encrypt(this.key(), data);
    }

    private PublicKeyInterface key;
    private EncryptionCipherInterface cipher;
}
