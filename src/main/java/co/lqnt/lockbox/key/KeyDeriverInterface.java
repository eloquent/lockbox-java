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
 * The interface implemented by encryption key derivers.
 */
public interface KeyDeriverInterface
{
    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     *
     * @return The derived key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public DerivedKeyDataInterface deriveKeyFromPassword(
        final List<Character> password,
        final int iterations
    ) throws
        InvalidKeyParameterException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param name        The name.
     *
     * @return The derived key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public DerivedKeyDataInterface deriveKeyFromPassword(
        final List<Character> password,
        final int iterations,
        final String name
    ) throws
        InvalidKeyParameterException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param name        The name.
     * @param description The description.
     *
     * @return The derived key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public DerivedKeyDataInterface deriveKeyFromPassword(
        final List<Character> password,
        final int iterations,
        final String name,
        final String description
    ) throws
        InvalidKeyParameterException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param salt        The salt to use.
     *
     * @return The derived key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface deriveKeyFromPassword(
        final List<Character> password,
        final int iterations,
        final List<Byte> salt
    ) throws
        InvalidKeyParameterException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param salt        The salt to use.
     * @param name        The name.
     * @param description The description.
     *
     * @return The derived key.
     * @throws InvalidKeyParameterException If any of the supplied parameters is invalid.
     */
    public KeyInterface deriveKeyFromPassword(
        final List<Character> password,
        final int iterations,
        final List<Byte> salt,
        final String name,
        final String description
    ) throws
        InvalidKeyParameterException;
}
