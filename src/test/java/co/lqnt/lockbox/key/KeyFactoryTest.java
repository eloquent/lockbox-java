/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeyFactoryTest
{
    public KeyFactoryTest()
    {
        this.factory = new KeyFactory();

        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
    }

    @Test
    public void testCreateKey() throws Throwable
    {
        KeyInterface key = this.factory.createKey(this.bytes16, this.bytes28, "name", "description");

        Assert.assertEquals(key.encryptionSecret(), this.bytes16);
        Assert.assertEquals(key.authenticationSecret(), this.bytes28);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertEquals(key.description().get(), "description");
    }

    @Test
    public void testCreateKeyNoDescription() throws Throwable
    {
        KeyInterface key = this.factory.createKey(this.bytes16, this.bytes28, "name");

        Assert.assertEquals(key.encryptionSecret(), this.bytes16);
        Assert.assertEquals(key.authenticationSecret(), this.bytes28);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertFalse(key.description().isPresent());
    }

    @Test
    public void testCreateKeyNoNameOrDescription() throws Throwable
    {
        KeyInterface key = this.factory.createKey(this.bytes16, this.bytes28);

        Assert.assertEquals(key.encryptionSecret(), this.bytes16);
        Assert.assertEquals(key.authenticationSecret(), this.bytes28);
        Assert.assertFalse(key.name().isPresent());
        Assert.assertFalse(key.description().isPresent());
    }

    @Test
    public void testInstance()
    {
        KeyFactory instance = KeyFactory.instance();

        Assert.assertSame(KeyFactory.instance(), instance);
    }

    final private KeyFactory factory;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
}
