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

public class CipherFinalizedExceptionTest
{
    public CipherFinalizedExceptionTest()
    {
        this.cipher = new EncryptCipher();
    }
    
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        CipherFinalizedException exception = new CipherFinalizedException(this.cipher, cause);

        Assert.assertSame(exception.cipher(), this.cipher);
        Assert.assertEquals(exception.getMessage(), "The cipher is already finalized.");
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        CipherFinalizedException exception = new CipherFinalizedException(this.cipher);

        Assert.assertSame(exception.cipher(), this.cipher);
        Assert.assertEquals(exception.getMessage(), "The cipher is already finalized.");
        Assert.assertNull(exception.getCause());
    }
    
    final private CipherInterface cipher;
}
