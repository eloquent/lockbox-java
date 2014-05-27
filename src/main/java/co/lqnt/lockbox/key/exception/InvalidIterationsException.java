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
 * The number of iterations is invalid.
 */
final public class InvalidIterationsException extends
    InvalidKeyParameterException
{
    /**
     * Construct a new invalid iterations exception.
     *
     * @param iterations The invalid secret size.
     */
    public InvalidIterationsException(final int iterations)
    {
        this(iterations, null);
    }

    /**
     * Construct a new invalid iterations exception.
     *
     * @param iterations  The invalid secret size.
     * @param cause The cause.
     */
    public InvalidIterationsException(
        final int iterations,
        final Throwable cause
    ) {
        super(String.format("Invalid iterations %d.", iterations), cause);

        this.iterations = iterations;
    }

    /**
     * Get the invalid iterations.
     *
     * @return The iterations.
     */
    public int iterations()
    {
        return this.iterations;
    }

    final private int iterations;
}
