/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util.codec.exception;

/**
 * Decoding failed.
 */
final public class DecodingFailedException extends Exception
{
    /**
     * Construct a new decoding failed exception.
     *
     * @param cause The cause.
     */
    public DecodingFailedException(final Throwable cause)
    {
        super("Decoding failed.", cause);
    }

    /**
     * Construct a new decoding failed exception.
     */
    public DecodingFailedException()
    {
        this(null);
    }
}
