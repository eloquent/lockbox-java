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
 * The interface implemented by Lockbox decryption ciphers.
 */
public interface DecryptionCipherInterface
{
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
        throws DecryptionFailedException;

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
        throws DecryptionFailedException;
}
