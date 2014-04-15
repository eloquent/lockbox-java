/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class InvalidSaltSizeExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        InvalidSaltSizeException exception = new InvalidSaltSizeException(111, cause);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(exception.getMessage(), "Invalid salt size 111. Salt must be 512 bits.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        InvalidSaltSizeException exception = new InvalidSaltSizeException(111);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(exception.getMessage(), "Invalid salt size 111. Salt must be 512 bits.");
        Assert.assertNull(exception.getCause());
    }
}
