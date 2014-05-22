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
 * The cipher is already finalized.
 */
final public class CipherNotInitializedException extends CipherStateException
{
    /**
     * Construct a new cipher not initialized exception.
     *
     * @param cipher The cipher.
     */
    public CipherNotInitializedException(final CipherInterface cipher)
    {
        this(cipher, null);
    }

    /**
     * Construct a new cipher not initialized exception.
     *
     * @param cipher The cipher.
     * @param cause  The cause.
     */
    public CipherNotInitializedException(
        final CipherInterface cipher,
        final Throwable cause
    ) {
        super(cipher, "The cipher is not initialized finalized.", cause);
    }
}
