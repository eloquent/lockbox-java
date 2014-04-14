/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.util.exception;

/**
 * Attempted to access erased data.
 */
final public class ErasedDataException extends RuntimeException
{
    /**
     * Construct a new erased data exception.
     */
    public ErasedDataException()
    {
        this(null);
    }

    /**
     * Construct a new erased data exception.
     *
     * @param cause The cause.
     */
    public ErasedDataException(final Throwable cause)
    {
        super("Attempted to access erased data.", cause);
    }
}
