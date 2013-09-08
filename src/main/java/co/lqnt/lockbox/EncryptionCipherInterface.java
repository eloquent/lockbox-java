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
 * The interface implemented by Lockbox encryption ciphers.
 */
public interface EncryptionCipherInterface
{
    /**
     * Encrypt a data packet.
     *
     * @param key  They key to encrypt with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public byte[] encrypt(final PublicKeyInterface key, final byte[] data);

    /**
     * Encrypt a data packet.
     *
     * @param key  They key to encrypt with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     */
    public byte[] encrypt(final PrivateKeyInterface key, final byte[] data);
}
