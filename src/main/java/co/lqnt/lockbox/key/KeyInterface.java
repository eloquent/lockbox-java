/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.cipher.parameters.CipherParametersInterface;
import com.google.common.base.Optional;
import java.util.List;

/**
 * The interface implemented by encryption keys.
 */
public interface KeyInterface extends CipherParametersInterface
{
    /**
     * Get the encrypt secret.
     *
     * @return The encrypt secret.
     */
    public List<Byte> encryptSecret();

    /**
     * Get the size of the encrypt secret in bytes.
     *
     * @return The size of the encrypt secret in bytes.
     */
    public int encryptSecretBytes();

    /**
     * Get the size of the encrypt secret in bits.
     *
     * @return The size of the encrypt secret in bits.
     */
    public int encryptSecretBits();

    /**
     * Get the auth secret.
     *
     * @return The auth secret.
     */
    public List<Byte> authSecret();

    /**
     * Get the size of the auth secret in bytes.
     *
     * @return The size of the auth secret in bytes.
     */
    public int authSecretBytes();

    /**
     * Get the size of the auth secret in bits.
     *
     * @return The size of the auth secret in bits.
     */
    public int authSecretBits();

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
