/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.exception;

/**
 * The supplied output array is too small to contain the produced data.
 */
final public class OutputSizeException extends RuntimeException
{
    /**
     * Construct a new output size exception.
     *
     * @param availableSize The available output size.
     * @param requiredSize  The required output size.
     */
    public OutputSizeException(final int availableSize, final int requiredSize)
    {
        this(availableSize, requiredSize, null);
    }

    /**
     * Construct a new output size exception.
     *
     * @param availableSize The available output size.
     * @param requiredSize  The required output size.
     * @param cause         The cause.
     */
    public OutputSizeException(
        final int availableSize,
        final int requiredSize,
        final Throwable cause
    ) {
        super(
            String.format(
                "Available output size %d is insufficient " +
                    "to store %d bytes of output.",
                availableSize,
                requiredSize
            ),
            cause
        );

        this.availableSize = availableSize;
        this.requiredSize = requiredSize;
    }

    /**
     * Get the available output size.
     *
     * @return The available size.
     */
    public int availableSize()
    {
        return this.availableSize;
    }

    /**
     * Get the required output size.
     *
     * @return The required size.
     */
    public int requiredSize()
    {
        return this.requiredSize;
    }

    final private int availableSize;
    final private int requiredSize;
}
