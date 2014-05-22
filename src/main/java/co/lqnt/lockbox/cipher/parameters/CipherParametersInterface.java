/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.parameters;

/**
 * The interface implemented by cipher parameters.
 */
public interface CipherParametersInterface
{
    /**
     * Erase these parameters, removing any sensitive data.
     */
    public void erase();
}
