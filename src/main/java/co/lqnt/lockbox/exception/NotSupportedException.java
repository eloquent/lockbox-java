/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.exception;

/**
 * Lockbox is not supported by this runtime environment.
 */
final public class NotSupportedException extends Exception
{
    /**
     * Construct a new not supported exception.
     *
     * @param cause The cause.
     */
    public NotSupportedException(final Throwable cause)
    {
        super("Lockbox is not supported by this runtime environment.", cause);
    }

    /**
     * Construct a new not supported exception.
     */
    public NotSupportedException()
    {
        this(null);
    }
}
