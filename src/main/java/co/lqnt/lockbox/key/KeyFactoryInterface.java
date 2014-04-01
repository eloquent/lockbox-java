/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

/**
 * The interface implemented by encryption key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a new key from existing key data.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     *
     * @return The key.
     */
    public KeyInterface createKey(
        final byte[] encryptionSecret,
        final byte[] authenticationSecret
    );

    /**
     * Create a new key from existing key data.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     *
     * @return The key.
     */
    public KeyInterface createKey(
        final byte[] encryptionSecret,
        final byte[] authenticationSecret,
        final String name
    );

    /**
     * Create a new key from existing key data.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     * @param description          The description.
     *
     * @return The key.
     */
    public KeyInterface createKey(
        final byte[] encryptionSecret,
        final byte[] authenticationSecret,
        final String name,
        final String description
    );
}
