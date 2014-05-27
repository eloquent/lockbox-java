/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key.generator;

import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.key.exception.InvalidKeyParameterException;

/**
 * The interface implemented by encryption key generators.
 */
public interface KeyGeneratorInterface
{
    /**
     * Generate a new key.
     *
     * @return The generated key.
     */
    public KeyInterface generateKey();

    /**
     * Generate a new key.
     *
     * @param name The name.
     *
     * @return The generated key.
     */
    public KeyInterface generateKey(final String name);

    /**
     * Generate a new key.
     *
     * @param name The name.
     * @param description The description.
     *
     * @return The generated key.
     */
    public KeyInterface generateKey(
        final String name,
        final String description
    );

    /**
     * Generate a new key.
     *
     * @param encryptSecretBits The size of the encrypt secret in bits.
     * @param authSecretBits    The size of the auth secret in bits.
     *
     * @return The generated key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface generateKey(
        final int encryptSecretBits,
        final int authSecretBits
    ) throws
        InvalidKeyParameterException;

    /**
     * Generate a new key.
     *
     * @param name              The name.
     * @param description       The description.
     * @param encryptSecretBits The size of the encrypt secret in bits.
     * @param authSecretBits    The size of the auth secret in bits.
     *
     * @return The generated key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface generateKey(
        final String name,
        final String description,
        final int encryptSecretBits,
        final int authSecretBits
    ) throws
        InvalidKeyParameterException;
}