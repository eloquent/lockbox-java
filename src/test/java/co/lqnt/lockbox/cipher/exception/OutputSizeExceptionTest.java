/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class OutputSizeExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        OutputSizeException exception = new OutputSizeException(111, 222, cause);

        Assert.assertEquals(111, exception.availableSize());
        Assert.assertEquals(222, exception.requiredSize());
        Assert.assertEquals(exception.getMessage(), "Available output size 111 is insufficient to store 222 bytes of output.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        OutputSizeException exception = new OutputSizeException(111, 222);

        Assert.assertEquals(111, exception.availableSize());
        Assert.assertEquals(222, exception.requiredSize());
        Assert.assertEquals(exception.getMessage(), "Available output size 111 is insufficient to store 222 bytes of output.");
        Assert.assertNull(exception.getCause());
    }
}
