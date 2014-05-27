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
 * The supplied key parameter is invalid.
 */
abstract public class InvalidKeyParameterException extends Exception
{
    /**
     * Construct a new invalid key parameter exception.
     *
     * @param message The message.
     * @param cause   The cause.
     */
    public InvalidKeyParameterException(
        final String message,
        final Throwable cause
    ) {
        super(message, cause);
    }
}
