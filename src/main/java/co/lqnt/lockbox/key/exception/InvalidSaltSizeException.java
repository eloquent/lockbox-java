/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key.exception;

/**
 * The salt size is invalid.
 */
final public class InvalidSaltSizeException extends InvalidKeyParameterException
{
    /**
     * Construct a new invalid salt size exception.
     *
     * @param size The invalid secret size.
     */
    public InvalidSaltSizeException(final int size)
    {
        this(size, null);
    }

    /**
     * Construct a new invalid salt size exception.
     *
     * @param size  The invalid secret size.
     * @param cause The cause.
     */
    public InvalidSaltSizeException(
        final int size,
        final Throwable cause
    ) {
        super(
            String.format("Invalid salt size %d. Salt must be 512 bits.", size),
            cause
        );

        this.size = size;
    }

    /**
     * Get the invalid secret size.
     *
     * @return The size.
     */
    public int size()
    {
        return this.size;
    }

    final private int size;
}
