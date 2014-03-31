/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

/**
 * Generates secure random data.
 */
public class SecureRandom implements SecureRandomInterface
{
    /**
     * Construct a new secure random generator.
     *
     * Using this constructor will instantiate the JCE SecureRandom instance
     * only when it is requested, which can improve performance, as
     * instantiation of JCE SecureRandom instances (without a seed) can be a
     * relatively costly operation.
     */
    public SecureRandom()
    {
        this.jceSecureRandom = null;
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

    /**
     * Get the internal JCE secure random generator.
     *
     * @return The internal random generator.
     */
    public java.security.SecureRandom jceSecureRandom()
    {
        if (null == this.jceSecureRandom) {
            this.jceSecureRandom = new java.security.SecureRandom();
        }

        return this.jceSecureRandom;
    }

    private java.security.SecureRandom jceSecureRandom;
}
