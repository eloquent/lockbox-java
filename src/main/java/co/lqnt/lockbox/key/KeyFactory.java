/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidAuthenticationSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidEncryptionSecretSizeException;
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
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     *
     * @return The key.
     * @throws InvalidEncryptionSecretSizeException     If the encryption secret is an invalid size.
     * @throws InvalidAuthenticationSecretSizeException If the authentication secret is an invalid size.
     */
    public KeyInterface createKey(
        final List<Byte> encryptionSecret,
        final List<Byte> authenticationSecret
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException
    {
        return new Key(encryptionSecret, authenticationSecret);
    }

    /**
     * Create a new key from existing key data.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     *
     * @return The key.
     * @throws InvalidEncryptionSecretSizeException     If the encryption secret is an invalid size.
     * @throws InvalidAuthenticationSecretSizeException If the authentication secret is an invalid size.
     */
    public KeyInterface createKey(
        final List<Byte> encryptionSecret,
        final List<Byte> authenticationSecret,
        final String name
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException
    {
        return new Key(encryptionSecret, authenticationSecret, name);
    }

    /**
     * Create a new key from existing key data.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     * @param description          The description.
     *
     * @return The key.
     * @throws InvalidEncryptionSecretSizeException     If the encryption secret is an invalid size.
     * @throws InvalidAuthenticationSecretSizeException If the authentication secret is an invalid size.
     */
    public KeyInterface createKey(
        final List<Byte> encryptionSecret,
        final List<Byte> authenticationSecret,
        final String name,
        final String description
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException
    {
        return new Key(
            encryptionSecret,
            authenticationSecret,
            name,
            description
        );
    }

    static private KeyFactory instance;
}
