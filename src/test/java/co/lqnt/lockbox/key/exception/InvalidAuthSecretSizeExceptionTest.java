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

public class InvalidAuthSecretSizeExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        InvalidAuthSecretSizeException exception = new InvalidAuthSecretSizeException(111, cause);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(
            exception.getMessage(),
            "Invalid auth secret size 111. Auth secret must be 224, 256, 384, or 512 bits."
        );
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        InvalidAuthSecretSizeException exception = new InvalidAuthSecretSizeException(111);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(
            exception.getMessage(),
            "Invalid auth secret size 111. Auth secret must be 224, 256, 384, or 512 bits."
        );
        Assert.assertNull(exception.getCause());
    }
}
