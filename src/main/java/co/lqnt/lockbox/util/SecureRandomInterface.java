/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

/**
 * The interface implemented by secure random generators.
 */
public interface SecureRandomInterface
{
    /**
     * Generate a random byte array.
     *
     * @param size The size of the random data to generate.
     *
     * @return The random byte array
     */
    public byte[] generate(int size);
}
