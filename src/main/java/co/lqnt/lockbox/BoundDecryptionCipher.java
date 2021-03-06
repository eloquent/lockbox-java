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

/**
 * The standard Lockbox decryption cipher, with a bound key.
 */
public class BoundDecryptionCipher implements BoundDecryptionCipherInterface
{
    /**
     * Construct a new bound decryption cipher.
     *
     * @param key The key to use.
     */
    public BoundDecryptionCipher(final PrivateKeyInterface key)
    {
        this(key, new DecryptionCipher());
    }

    /**
     * Construct a new bound decryption cipher.
     *
     * @param key    The key to use.
     * @param cipher The cipher to use.
     */
    public BoundDecryptionCipher(
        final PrivateKeyInterface key,
        final DecryptionCipherInterface cipher
    ) {
        this.key = key;
        this.cipher = cipher;
    }

    /**
     * Get the key.
     *
     * @return The key.
     */
    public PrivateKeyInterface key()
    {
        return this.key;
    }

    /**
     * Get the cipher.
     *
     * @return The cipher.
     */
    public DecryptionCipherInterface cipher()
    {
        return this.cipher;
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
        return this.cipher().decrypt(this.key(), data);
    }

    /**
     * Decrypt a data packet.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     */
    public String decrypt(final String data) throws DecryptionFailedException
    {
        return this.cipher().decrypt(this.key(), data);
    }

    private PrivateKeyInterface key;
    private DecryptionCipherInterface cipher;
}
