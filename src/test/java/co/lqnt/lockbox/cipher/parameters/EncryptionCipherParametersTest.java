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

public class EncryptionCipherParametersTest
{
    public EncryptionCipherParametersTest() throws Throwable
    {
        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);
        this.parameters = new EncryptionCipherParameters(this.key, this.bytes16);
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.key, this.parameters.key());
        Assert.assertEquals(this.bytes16, this.parameters.iv());
    }

    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
    final private Key key;
    final private EncryptionCipherParameters parameters;
}
