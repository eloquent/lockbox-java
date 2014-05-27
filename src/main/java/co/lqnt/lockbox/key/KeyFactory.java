/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidKeyParameterException;
import java.util.List;

/**
 * Creates encryption keys.
 */
public class KeyFactory implements KeyFactoryInterface
{
    /**
     * Get the static instance of this factory.
     *
     * @return The static factory.
     */
    static public KeyFactory instance()
    {
        if (null == KeyFactory.instance) {
            KeyFactory.instance = new KeyFactory();
        }

        return KeyFactory.instance;
    }

    /**
     * Create a new key from existing key data.
     *
     * @param encryptSecret The encrypt secret.
     * @param authSecret    The auth secret.
     *
     * @return The key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface createKey(
        final List<Byte> encryptSecret,
        final List<Byte> authSecret
    ) throws
        InvalidKeyParameterException
    {
        return new Key(encryptSecret, authSecret);
    }

    /**
     * Create a new key from existing key data.
     *
     * @param encryptSecret The encrypt secret.
     * @param authSecret    The auth secret.
     * @param name          The name.
     *
     * @return The key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface createKey(
        final List<Byte> encryptSecret,
        final List<Byte> authSecret,
        final String name
    ) throws
        InvalidKeyParameterException
    {
        return new Key(encryptSecret, authSecret, name);
    }

    /**
     * Create a new key from existing key data.
     *
     * @param encryptSecret The encrypt secret.
     * @param authSecret    The auth secret.
     * @param name          The name.
     * @param description   The description.
     *
     * @return The key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface createKey(
        final List<Byte> encryptSecret,
        final List<Byte> authSecret,
        final String name,
        final String description
    ) throws
        InvalidKeyParameterException
    {
        return new Key(encryptSecret, authSecret, name, description);
    }

    static private KeyFactory instance;
}
