/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result;

/**
 * Represents the available result types.
 */
public enum CipherResultType
{
    /**
     * Indicates a successful result.
     */
    SUCCESS (true),

    /**
     * The input data was an invalid size and could not be processed.
     */
    INVALID_SIZE (false),

    /**
     * The input data was not encoded, or the encoding was invalid.
     */
    INVALID_ENCODING (false),

    /**
     * One or more message authentication codes were invalid.
     */
    INVALID_MAC (false),

    /**
     * An unsupported version identifier was encountered.
     */
    UNSUPPORTED_VERSION (false),

    /**
     * An unsupported type identifier was encountered.
     */
    UNSUPPORTED_TYPE (false),

    /**
     * The input data was not correctly padded.
     */
    INVALID_PADDING (false),

    /**
     * The requested number of hash iterations exceeded the configured limit.
     */
    TOO_MANY_ITERATIONS (false);

    /**
     * Returns true if this result type indicates a successful result.
     *
     * @return True if successful.
     */
    public boolean isSuccessful()
    {
        return this.isSuccessful;
    }

    /**
     * Construct a new cipher result type.
     *
     * @param isSuccessful True if this result type indicates a successful result.
     */
    CipherResultType(final boolean isSuccessful)
    {
        this.isSuccessful = isSuccessful;
    }

    final private boolean isSuccessful;
}
