/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.Test;

public class SecureRandomTest
{
    public SecureRandomTest()
    {
        this.jceSecureRandom = new java.security.SecureRandom("foobar".getBytes(Charset.forName("US-ASCII")));
        this.random = new SecureRandom(jceSecureRandom);
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.random.jceSecureRandom(), this.jceSecureRandom);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.random = new SecureRandom();

        Assert.assertTrue(this.random.jceSecureRandom() instanceof java.security.SecureRandom);
    }

    @Test
    public void testGenerate() throws Throwable
    {
        byte[] data = this.random.generate(16);

        Assert.assertEquals(data.length, 16);
    }

    private java.security.SecureRandom jceSecureRandom;
    private SecureRandom random;
}
