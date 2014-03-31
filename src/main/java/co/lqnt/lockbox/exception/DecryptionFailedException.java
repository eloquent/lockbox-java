/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.exception;

/**
 * Decryption failed.
 */
final public class DecryptionFailedException extends Exception
{
    /**
     * Construct a new decryption failed exception.
     *
     * @param cause The cause.
     */
    public DecryptionFailedException(final Throwable cause)
    {
        super("Decryption failed.", cause);
    }

    /**
     * Construct a new decryption failed exception.
     */
    public DecryptionFailedException()
    {
        this(null);
    }
}
