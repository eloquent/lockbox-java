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
 * Unable to read a PEM key pair from the supplied data.
 */
final public class KeyPairReadException extends Exception
{
    /**
     * Construct a new key pair read exception.
     *
     * @param cause The cause.
     */
    public KeyPairReadException(final Throwable cause)
    {
        super(
            "Unable to read a PEM key pair from the supplied data.",
            cause
        );
    }

    /**
     * Construct a new key pair read exception.
     */
    public KeyPairReadException()
    {
        this(null);
    }
}
