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
 * Unable to read a public key from the supplied data.
 */
final public class PublicKeyReadException extends Exception
{
    /**
     * Construct a new public key read exception.
     *
     * @param cause The cause.
     */
    public PublicKeyReadException(final Throwable cause)
    {
        super(
            "Unable to read a public key from the supplied data.",
            cause
        );
    }

    /**
     * Construct a new public key read exception.
     */
    public PublicKeyReadException()
    {
        this(null);
    }
}
