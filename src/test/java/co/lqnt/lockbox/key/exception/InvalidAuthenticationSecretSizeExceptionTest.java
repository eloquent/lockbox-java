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

public class InvalidAuthenticationSecretSizeExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        InvalidAuthenticationSecretSizeException exception = new InvalidAuthenticationSecretSizeException(111, cause);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(exception.getMessage(), "Invalid authentication secret size 111.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        InvalidAuthenticationSecretSizeException exception = new InvalidAuthenticationSecretSizeException(111);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(exception.getMessage(), "Invalid authentication secret size 111.");
        Assert.assertNull(exception.getCause());
    }
}
