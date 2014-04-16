/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.key.KeyInterface;
import java.util.ArrayList;
import java.util.List;

/**
 * Parameters for the Lockbox key-based cipher.
 */
public class LockboxKeyCipherParameters implements
    LockboxKeyCipherParametersInterface
{
    /**
     * Construct a new Lockbox key cipher parameters instance.
     *
     * @param key The key to use.
     * @param iv  The initialization vector to use.
     */
    public LockboxKeyCipherParameters(
        final KeyInterface key,
        final List<Byte> iv
    ) {
        this.key = key;
        this.iv = new ArrayList<Byte>(iv);
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

    /**
     * Get the initialization vector.
     *
     * @return The initialization vector.
     */
    public List<Byte> iv()
    {
        return this.iv;
    }

    final private KeyInterface key;
    final private List<Byte> iv;
}
