/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key.deriver;

import co.lqnt.lockbox.key.Key;
import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.key.deriver.DerivedKeyData;
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

public class DerivedKeyDataTest
{
    public DerivedKeyDataTest() throws Throwable
    {
        this.bytes32 = Bytes.asList(
            "12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII"))
        );
        this.bytes64 = Bytes.asList(
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(Charset.forName("US-ASCII"))
        );
        this.key = new Key(this.bytes32, this.bytes32);
        this.data = new DerivedKeyData(this.key, this.bytes64);
    }

    @Test
    public void testConstructor() throws Throwable
    {
        Assert.assertEquals(this.data.key(), this.key);
        Assert.assertEquals(this.data.salt(), this.bytes64);
    }

    final private DerivedKeyData data;
    final private KeyInterface key;
    final private List<Byte> bytes32;
    final private List<Byte> bytes64;
}
