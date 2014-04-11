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
 * The encryption secret size is invalid.
 */
final public class InvalidEncryptionSecretSizeException extends Exception
{
    /**
     * Construct a new invalid encryption secret size exception.
     *
     * @param size The invalid secret size.
     */
    public InvalidEncryptionSecretSizeException(final int size)
    {
        this(size, null);
    }

    /**
     * Construct a new invalid encryption secret size exception.
     *
     * @param size  The invalid secret size.
     * @param cause The cause.
     */
    public InvalidEncryptionSecretSizeException(
        final int size,
        final Throwable cause
    ) {
        super(
            String.format(
                "Invalid encryption secret size %d. " +
                "Encryption secret must be 128, 192, or 256 bits.",
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
