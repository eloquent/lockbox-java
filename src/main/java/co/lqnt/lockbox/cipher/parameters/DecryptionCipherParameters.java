/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.parameters;

import co.lqnt.lockbox.key.KeyInterface;

/**
 * Parameters for the key decryption cipher.
 */
public class DecryptionCipherParameters implements
    DecryptionCipherParametersInterface
{
    /**
     * Construct a new key decryption cipher parameters instance.
     *
     * @param key The key to use.
     */
    public DecryptionCipherParameters(final KeyInterface key)
    {
        this.key = key;
    }

    /**
     * Get the key.
     *
     * @return The key.
     */
    public KeyInterface key()
    {
        return this.key;
    }

    final private KeyInterface key;
}
