/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result.factory;

import co.lqnt.lockbox.cipher.result.CipherResultInterface;
import co.lqnt.lockbox.cipher.result.CipherResultType;

/**
 * The interface implemented by cipher result factories.
 */
public interface CipherResultFactoryInterface
{
    /**
     * Create a new cipher result.
     *
     * @param type The result type.
     *
     * @return The newly created result.
     */
    public CipherResultInterface createResult(final CipherResultType type);
}
