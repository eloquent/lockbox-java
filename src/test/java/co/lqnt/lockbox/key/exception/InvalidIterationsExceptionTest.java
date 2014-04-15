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

public class InvalidIterationsExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        InvalidIterationsException exception = new InvalidIterationsException(0, cause);

        Assert.assertEquals(0, exception.iterations());
        Assert.assertEquals(exception.getMessage(), "Invalid iterations 0.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        InvalidIterationsException exception = new InvalidIterationsException(0);

        Assert.assertEquals(0, exception.iterations());
        Assert.assertEquals(exception.getMessage(), "Invalid iterations 0.");
        Assert.assertNull(exception.getCause());
    }
}
