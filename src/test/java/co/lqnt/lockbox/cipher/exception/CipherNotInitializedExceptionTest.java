/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.exception;

import co.lqnt.lockbox.cipher.CipherInterface;
import co.lqnt.lockbox.cipher.EncryptCipher;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CipherNotInitializedExceptionTest
{
    public CipherNotInitializedExceptionTest()
    {
        this.cipher = new EncryptCipher();
    }
    
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        CipherNotInitializedException exception = new CipherNotInitializedException(this.cipher, cause);

        Assert.assertSame(this.cipher, exception.cipher());
        Assert.assertEquals(exception.getMessage(), "The cipher is not initialized.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        CipherNotInitializedException exception = new CipherNotInitializedException(this.cipher);

        Assert.assertSame(this.cipher, exception.cipher());
        Assert.assertEquals(exception.getMessage(), "The cipher is not initialized.");
        Assert.assertNull(exception.getCause());
    }
    
    private CipherInterface cipher;
}
