/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.random;

/**
 * The interface implemented by random data sources.
 */
public interface RandomSourceInterface
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
