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
import com.google.common.base.Optional;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Cipher parameters for encrypting data with a key.
 */
public class EncryptParameters implements EncryptParametersInterface
{
    /**
     * Construct a new encrypt parameters instance.
     *
     * @param key The key to use.
     * @param iv  The initialization vector to use.
     */
    public EncryptParameters(
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
    public Optional<List<Byte>> iv()
    {
        if (null == this.iv) {
            return Optional.<List<Byte>>absent();
        }

        return Optional.<List<Byte>>of(new ArrayList<Byte>(this.iv));
    }

    /**
     * Erase these parameters, removing any sensitive data.
     */
    public void erase()
    {
        this.key().erase();

        Collections.fill(this.iv, (byte) 0);
    }

    final private KeyInterface key;
    final private List<Byte> iv;
}
