/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.parameters;

import co.lqnt.lockbox.key.Key;
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

public class EncryptParametersTest
{
    public EncryptParametersTest() throws Throwable
    {
        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);
    }

    @Test
    public void testConstructor()
    {
        this.parameters = new EncryptParameters(this.key, this.bytes16);

        Assert.assertSame(this.parameters.key(), this.key);
        Assert.assertTrue(this.parameters.iv().isPresent());
        Assert.assertEquals(this.parameters.iv().get(), this.bytes16);
    }

    @Test
    public void testConstructorKeyOnly()
    {
        this.parameters = new EncryptParameters(this.key);

        Assert.assertSame(this.parameters.key(), this.key);
        Assert.assertFalse(this.parameters.iv().isPresent());
    }

    @Test
    public void testErase() throws Throwable
    {
        this.parameters = new EncryptParameters(this.key, this.bytes16);
        this.parameters.erase();
        List<Byte> expectedEncryptSecret =
            Bytes.asList("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(Charset.forName("US-ASCII")));
        List<Byte> expectedAuthSecret =
            Bytes.asList(
                "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(Charset.forName("US-ASCII"))
            );

        Assert.assertEquals(this.parameters.key().encryptSecret(), expectedEncryptSecret);
        Assert.assertEquals(this.parameters.key().authSecret(), expectedAuthSecret);
        Assert.assertFalse(this.parameters.key().name().isPresent());
        Assert.assertFalse(this.parameters.key().description().isPresent());
        Assert.assertFalse(this.parameters.iv().isPresent());
    }

    private EncryptParameters parameters;
    final private Key key;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
}
