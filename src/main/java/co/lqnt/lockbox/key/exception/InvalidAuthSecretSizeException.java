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
 * The auth secret size is invalid.
 */
final public class InvalidAuthSecretSizeException extends Exception
{
    /**
     * Construct a new invalid auth secret size exception.
     *
     * @param size The invalid secret size.
     */
    public InvalidAuthSecretSizeException(final int size)
    {
        this(size, null);
    }

    /**
     * Construct a new invalid auth secret size exception.
     *
     * @param size  The invalid secret size.
     * @param cause The cause.
     */
    public InvalidAuthSecretSizeException(
        final int size,
        final Throwable cause
    ) {
        super(
            String.format(
                "Invalid auth secret size %d. " +
                "Auth secret must be 224, 256, 384, or 512 bits.",
                size
            ),
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
