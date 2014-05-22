/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.exception;

import co.lqnt.lockbox.cipher.CipherInterface;

/**
 * The cipher state is not valid for the requested operation.
 */
abstract public class CipherStateException extends RuntimeException
{
    /**
     * Construct a new cipher state exception.
     *
     * @param cipher  The cipher.
     * @param message The message.
     * @param cause   The cause.
     */
    public CipherStateException(
        final CipherInterface cipher,
        final String message,
        final Throwable cause
    ) {
        super(message, cause);

        this.cipher = cipher;
    }

    /**
     * Get the cipher.
     *
     * @return The cipher.
     */
    public CipherInterface cipher()
    {
        return this.cipher;
    }

    final private CipherInterface cipher;
}
