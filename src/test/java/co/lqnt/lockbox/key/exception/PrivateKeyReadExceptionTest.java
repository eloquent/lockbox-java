/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class PrivateKeyReadExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        PrivateKeyReadException exception = new PrivateKeyReadException(cause);

        Assert.assertEquals(exception.getMessage(), "Unable to read a private key from the supplied data.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        PrivateKeyReadException exception = new PrivateKeyReadException();

        Assert.assertEquals(exception.getMessage(), "Unable to read a private key from the supplied data.");
        Assert.assertNull(exception.getCause());
    }
}
