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

/**
 * The interface implemented by ciphers that decrypt data and use a bound key.
 */
public interface BoundDecryptionCipherInterface
{
    /**
     * Decrypt a data packet.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     */
    public byte[] decrypt(final byte[] data) throws DecryptionFailedException;

    /**
     * Decrypt a data packet.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     */
    public String decrypt(final String data) throws DecryptionFailedException;
}
