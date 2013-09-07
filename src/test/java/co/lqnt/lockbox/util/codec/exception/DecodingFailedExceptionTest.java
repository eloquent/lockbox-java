/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util.codec.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class DecodingFailedExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        DecodingFailedException exception = new DecodingFailedException(cause);

        Assert.assertEquals(exception.getMessage(), "Decoding failed.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        DecodingFailedException exception = new DecodingFailedException();

        Assert.assertEquals(exception.getMessage(), "Decoding failed.");
        Assert.assertNull(exception.getCause());
    }
}
