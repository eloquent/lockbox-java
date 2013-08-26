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
import java.security.spec.KeySpec;

/**
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a new private key.
     *
     * @param key The PEM formatted private key.
     *
     * @return The newly created private key.
     * @throws InvalidPrivateKeyException If the key is invalid.
     */
    public KeySpec createPrivateKey(final byte[] key)
        throws InvalidPrivateKeyException;

    /**
     * Create a new private key.
     *
     * @param key The PEM formatted private key.
     *
     * @return The newly created private key.
     * @throws InvalidPrivateKeyException If the key is invalid.
     */
    public KeySpec createPrivateKey(final String key)
        throws InvalidPrivateKeyException;

    /**
     * Create a new private key.
     *
     * @param key    The PEM formatted private key.
     * @param String The key password.
     *
     * @return The newly created private key.
     * @throws InvalidPrivateKeyException If the key is invalid.
     */
    public KeySpec createPrivateKey(final byte[] key, final String password)
        throws InvalidPrivateKeyException;

    /**
     * Create a new private key.
     *
     * @param key    The PEM formatted private key.
     * @param String The key password.
     *
     * @return The newly created private key.
     * @throws InvalidPrivateKeyException If the key is invalid.
     */
    public KeySpec createPrivateKey(final String key, final String password)
        throws InvalidPrivateKeyException;
}
