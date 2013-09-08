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
 * Generates secure random data.
 */
public class SecureRandom implements SecureRandomInterface
{
    /**
     * Construct a new secure random generator.
     */
    public SecureRandom()
    {
        this.jceSecureRandom = new java.security.SecureRandom();
    }

    /**
     * Construct a new secure random generator.
     *
     * @param jceSecureRandom The internal JCE secure random generator to use.
     */
    public SecureRandom(java.security.SecureRandom jceSecureRandom)
    {
        this.jceSecureRandom = jceSecureRandom;
    }

    /**
     * Get the internal JCE secure random generator.
     *
     * @return The internal random generator.
     */
    public java.security.SecureRandom jceSecureRandom()
    {
        return this.jceSecureRandom;
    }

    /**
     * Generate a random byte array.
     *
     * @param size The size of the random data to generate.
     *
     * @return The random byte array
     */
    public byte[] generate(int size)
    {
        byte[] random = new byte[size];
        this.jceSecureRandom().nextBytes(random);

        return random;
    }

    private java.security.SecureRandom jceSecureRandom;
}
