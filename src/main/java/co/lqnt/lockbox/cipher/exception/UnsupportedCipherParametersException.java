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
import co.lqnt.lockbox.cipher.parameters.CipherParametersInterface;

/**
 * The supplied parameters are not supported by the cipher.
 */
public class UnsupportedCipherParametersException extends RuntimeException
{
    /**
     * Construct a new unsupported cipher parameters exception.
     *
     * @param cipher     The cipher.
     * @param parameters The parameters.
     */
    public UnsupportedCipherParametersException(
        final CipherInterface cipher,
        final CipherParametersInterface parameters
    ) {
        this(cipher, parameters, null);
    }

    /**
     * Construct a new unsupported cipher parameters exception.
     *
     * @param cipher     The cipher.
     * @param parameters The parameters.
     * @param cause      The cause.
     */
    public UnsupportedCipherParametersException(
        final CipherInterface cipher,
        final CipherParametersInterface parameters,
        final Throwable cause
    ) {
        super(
            String.format(
                "Cipher of type %s does not support parameters of type %s.",
                cipher.getClass().getName(),
                parameters.getClass().getName()
            ),
            cause
        );

        this.cipher = cipher;
        this.parameters = parameters;
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

    /**
     * Get the parameters.
     *
     * @return The parameters.
     */
    public CipherParametersInterface parameters()
    {
        return this.parameters;
    }

    final private CipherInterface cipher;
    final private CipherParametersInterface parameters;
}
