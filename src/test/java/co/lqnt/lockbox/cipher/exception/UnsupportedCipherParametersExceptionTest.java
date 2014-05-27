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
import co.lqnt.lockbox.cipher.parameters.CipherParametersInterface;
import co.lqnt.lockbox.key.Key;
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

public class UnsupportedCipherParametersExceptionTest
{
    public UnsupportedCipherParametersExceptionTest() throws Throwable
    {
        this.cipher = new EncryptCipher();
        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.parameters = new Key(this.bytes16, this.bytes28);
    }
    
    @Test
    public void testException()
    {
        Exception cause = new Exception();
        UnsupportedCipherParametersException exception = new UnsupportedCipherParametersException(this.cipher, this.parameters, cause);

        Assert.assertSame(exception.cipher(), this.cipher);
        Assert.assertSame(exception.parameters(), this.parameters);
        Assert.assertEquals(
            exception.getMessage(),
            "Cipher of type " +
            "co.lqnt.lockbox.cipher.EncryptCipher" +
            " does not support parameters of type " +
            "co.lqnt.lockbox.key.Key" +
            "."
        );
        Assert.assertSame(exception.getCause(), cause);
    }

    @Test
    public void testExceptionWithoutCause()
    {
        UnsupportedCipherParametersException exception = new UnsupportedCipherParametersException(this.cipher, this.parameters);

        Assert.assertSame(exception.cipher(), this.cipher);
        Assert.assertSame(exception.parameters(), this.parameters);
        Assert.assertEquals(
            exception.getMessage(),
            "Cipher of type " +
            "co.lqnt.lockbox.cipher.EncryptCipher" +
            " does not support parameters of type " +
            "co.lqnt.lockbox.key.Key" +
            "."
        );
        Assert.assertNull(exception.getCause());
    }
    
    final private CipherInterface cipher;
    final private CipherParametersInterface parameters;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
}
