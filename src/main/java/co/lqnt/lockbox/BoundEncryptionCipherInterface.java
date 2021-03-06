/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

/**
 * The interface implemented by ciphers that encrypt data and use a bound key.
 */
public interface BoundEncryptionCipherInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public byte[] encrypt(final byte[] data);

    /**
     * Encrypt a data packet.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public String encrypt(final String data);
}
