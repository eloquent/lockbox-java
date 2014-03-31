/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

public class DecryptionFailedExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        DecryptionFailedException exception = new DecryptionFailedException(cause);

        Assert.assertEquals(exception.getMessage(), "Decryption failed.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        DecryptionFailedException exception = new DecryptionFailedException();

        Assert.assertEquals(exception.getMessage(), "Decryption failed.");
        Assert.assertNull(exception.getCause());
    }
}
