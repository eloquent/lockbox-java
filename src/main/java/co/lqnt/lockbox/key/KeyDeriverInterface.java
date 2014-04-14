/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidIterationsException;
import co.lqnt.lockbox.key.exception.InvalidSaltSizeException;
import co.lqnt.lockbox.util.ErasableDataInterface;

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
     * @throws InvalidIterationsException If the number of iterations is invalid.
     */
    public DerivedKeyDataInterface deriveKeyFromPassword(
        final ErasableDataInterface password,
        final int iterations
    ) throws
        InvalidIterationsException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param name        The name.
     *
     * @return The derived key.
     * @throws InvalidIterationsException If the number of iterations is invalid.
     */
    public DerivedKeyDataInterface deriveKeyFromPassword(
        final ErasableDataInterface password,
        final int iterations,
        final String name
    ) throws
        InvalidIterationsException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param name        The name.
     * @param description The description.
     *
     * @return The derived key.
     * @throws InvalidIterationsException If the number of iterations is invalid.
     */
    public DerivedKeyDataInterface deriveKeyFromPassword(
        final ErasableDataInterface password,
        final int iterations,
        final String name,
        final String description
    ) throws
        InvalidIterationsException;

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param salt        The salt to use.
     *
     * @return The derived key.
     * @throws InvalidIterationsException If the number of iterations is invalid.
     * @throws InvalidSaltSizeException   If the salt size is invalid.
     */
    public KeyInterface deriveKeyFromPassword(
        final ErasableDataInterface password,
        final int iterations,
        final byte[] salt
    ) throws
        InvalidIterationsException,
        InvalidSaltSizeException;

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
     * @throws InvalidIterationsException If the number of iterations is invalid.
     * @throws InvalidSaltSizeException   If the salt size is invalid.
     */
    public KeyInterface deriveKeyFromPassword(
        final ErasableDataInterface password,
        final int iterations,
        final byte[] salt,
        final String name,
        final String description
    ) throws
        InvalidIterationsException,
        InvalidSaltSizeException;
}
