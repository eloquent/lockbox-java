/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key.exception;

/**
 * Unable to read a private key from the supplied data.
 */
final public class PrivateKeyReadException extends Exception
{
    /**
     * Construct a new private key read exception.
     *
     * @param cause The cause.
     */
    public PrivateKeyReadException(final Throwable cause)
    {
        super(
            "Unable to read a private key from the supplied data.",
            cause
        );
    }

    /**
     * Construct a new private key read exception.
     */
    public PrivateKeyReadException()
    {
        this(null);
    }
}
