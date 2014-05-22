/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result;

import java.util.List;

/**
 * Represents the result of cipher processing.
 */
public class CipherResult extends AbstractCipherResult
{
    /**
     * Construct a new cipher result.
     *
     * @param type The result type.
     */
    public CipherResult(final CipherResultType type)
    {
        super(type);
    }

    /**
     * Construct a new cipher result.
     *
     * @param data The data.
     */
    public CipherResult(final List<Byte> data)
    {
        super(data);
    }

    /**
     * Construct a new cipher result.
     *
     * @param type The result type.
     * @param data The data.
     */
    public CipherResult(
        final CipherResultType type,
        final List<Byte> data
    ) {
        super(type, data);
    }
}
