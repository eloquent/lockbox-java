/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.SecureRandomInterface;

/**
 * Creates encryption keys.
 */
public class KeyFactory implements KeyFactoryInterface
{
    /**
     * Construct a new key factory.
     */
    public KeyFactory()
    {
        this.random = new SecureRandom();
    }

    /**
     * Construct a new key factory.
     *
     * @param random The secure random generator to use.
     */
    public KeyFactory(final SecureRandomInterface random)
    {
        this.random = random;
    }

    /**
     * Get the secure random generator.
     *
     * @return The secure random generator.
     */
    public SecureRandomInterface random()
    {
        return this.random;
    }

    private SecureRandomInterface random;
}
