/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key.exception;

import java.util.Arrays;

/**
 * The supplied key is not a valid PEM formatted private key.
 */
final public class InvalidPrivateKeyException extends Exception
{
    /**
     * Construct a new invalid private key exception.
     *
     * @param key   The key.
     * @param cause The cause.
     */
    public InvalidPrivateKeyException(final byte[] key, final Throwable cause)
    {
        super(
            "The supplied key is not a valid PEM formatted private key.",
            cause
        );

        this.key = Arrays.copyOf(key, key.length);
    }

    /**
     * Construct a new invalid private key exception.
     *
     * @param key The key.
     */
    public InvalidPrivateKeyException(final byte[] key)
    {
        this(key, null);
    }

    /**
     * Get the key.
     *
     * @return The key.
     */
    public byte[] key()
    {
        return Arrays.copyOf(this.key, this.key.length);
    }

    private byte[] key;
}
