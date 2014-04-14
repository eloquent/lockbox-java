/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import com.google.common.base.Optional;

/**
 * The interface implemented by encryption keys.
 */
public interface KeyInterface
{
    /**
     * Get the encryption secret.
     *
     * @return The encryption secret.
     */
    public byte[] encryptionSecret();

    /**
     * Get the size of the encryption secret in bytes.
     *
     * @return The size of the encryption secret in bytes.
     */
    public int encryptionSecretBytes();

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return The size of the encryption secret in bits.
     */
    public int encryptionSecretBits();

    /**
     * Get the authentication secret.
     *
     * @return The authentication secret.
     */
    public byte[] authenticationSecret();

    /**
     * Get the size of the authentication secret in bytes.
     *
     * @return The size of the authentication secret in bytes.
     */
    public int authenticationSecretBytes();

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return The size of the authentication secret in bits.
     */
    public int authenticationSecretBits();

    /**
     * Get the name.
     *
     * @return The name.
     */
    public Optional<String> name();

    /**
     * Get the description.
     *
     * @return The description.
     */
    public Optional<String> description();
}
