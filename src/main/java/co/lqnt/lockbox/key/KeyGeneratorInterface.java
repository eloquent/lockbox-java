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
     * @param encryptionSecretBits The size of the encryption secret in bits.
     * @param authenticationSecretBits The size of the authentication secret in bits.
     *
     * @return The generated key.
     * @throws InvalidEncryptionSecretSizeException     If the requested encryption secret size is invalid.
     * @throws InvalidAuthenticationSecretSizeException If the requested authentication secret size is invalid.
     */
    public KeyInterface generateKey(
        final int encryptionSecretBits,
        final int authenticationSecretBits
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException;

    /**
     * Generate a new key.
     *
     * @param name The name.
     * @param description The description.
     * @param encryptionSecretBits The size of the encryption secret in bits.
     * @param authenticationSecretBits The size of the authentication secret in bits.
     *
     * @return The generated key.
     * @throws InvalidEncryptionSecretSizeException     If the requested encryption secret size is invalid.
     * @throws InvalidAuthenticationSecretSizeException If the requested authentication secret size is invalid.
     */
    public KeyInterface generateKey(
        final String name,
        final String description,
        final int encryptionSecretBits,
        final int authenticationSecretBits
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException;
}
