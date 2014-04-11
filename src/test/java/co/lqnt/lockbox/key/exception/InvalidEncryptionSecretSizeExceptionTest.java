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

public class InvalidEncryptionSecretSizeExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        InvalidEncryptionSecretSizeException exception = new InvalidEncryptionSecretSizeException(111, cause);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(
            exception.getMessage(),
            "Invalid encryption secret size 111. Encryption secret must be 128, 192, or 256 bits."
        );
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        InvalidEncryptionSecretSizeException exception = new InvalidEncryptionSecretSizeException(111);

        Assert.assertEquals(111, exception.size());
        Assert.assertEquals(
            exception.getMessage(),
            "Invalid encryption secret size 111. Encryption secret must be 128, 192, or 256 bits."
        );
        Assert.assertNull(exception.getCause());
    }
}
