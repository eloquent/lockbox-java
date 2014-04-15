/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import java.util.List;

/**
 * The interface implemented by derived key data structures.
 */
public interface DerivedKeyDataInterface
{
    /**
     * Get the key.
     *
     * @return The key.
     */
    public KeyInterface key();

    /**
     * Get the salt used to derive the key.
     *
     * @return The salt.
     */
    public List<Byte> salt();
}