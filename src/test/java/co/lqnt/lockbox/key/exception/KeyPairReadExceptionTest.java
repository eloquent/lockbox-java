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

public class KeyPairReadExceptionTest
{
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        KeyPairReadException exception = new KeyPairReadException(cause);

        Assert.assertEquals(exception.getMessage(), "Unable to read a PEM key pair from the supplied data.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        KeyPairReadException exception = new KeyPairReadException();

        Assert.assertEquals(exception.getMessage(), "Unable to read a PEM key pair from the supplied data.");
        Assert.assertNull(exception.getCause());
    }
}
