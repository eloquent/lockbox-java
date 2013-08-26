/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidPrivateKeyException;
import java.security.KeyPair;

/**
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param key The PEM formatted private key.
     *
     * @return The key pair.
     * @throws InvalidPrivateKeyException If the key is invalid.
     */
    public KeyPair createKeyPair(final byte[] key)
        throws InvalidPrivateKeyException;
}
