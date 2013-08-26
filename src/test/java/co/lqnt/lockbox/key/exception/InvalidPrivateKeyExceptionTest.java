/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key.exception;

import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class InvalidPrivateKeyExceptionTest
{
    @BeforeClass
    public void setUp()
    {
        this.key = "foobar".getBytes(Charset.forName("US-ASCII"));
    }

    @Test
    public void testException()
    {
        Exception cause = new Exception();
        InvalidPrivateKeyException exception = new InvalidPrivateKeyException(
            this.key,
            cause
        );

        Assert.assertEquals(
            new String(exception.key(), Charset.forName("US-ASCII")),
            "foobar"
        );
        Assert.assertSame(exception.getCause(), cause);
    }

    private byte[] key;
}
