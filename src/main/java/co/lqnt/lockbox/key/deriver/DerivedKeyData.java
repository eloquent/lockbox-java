/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key.deriver;

import co.lqnt.lockbox.key.KeyInterface;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a derived key and the salt used in the derivation.
 */
public class DerivedKeyData implements DerivedKeyDataInterface
{
    /**
     * Construct a new derived key data structure.
     *
     * @param key  The key.
     * @param salt The salt used to derive the key.
     */
    public DerivedKeyData(final KeyInterface key, final List<Byte> salt)
    {
        this.key = key;
        this.salt = new ArrayList<Byte>(salt);
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
     * Get the salt used to derive the key.
     *
     * @return The salt.
     */
    public List<Byte> salt()
    {
        return new ArrayList<Byte>(this.salt);
    }

    final private KeyInterface key;
    final private List<Byte> salt;
}