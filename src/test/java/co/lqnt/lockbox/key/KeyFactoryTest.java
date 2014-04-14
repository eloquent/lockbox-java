/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeyFactoryTest
{
    public KeyFactoryTest()
    {
        this.encryptionSecret = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        this.authenticationSecret = "1234567890123456789012345678".getBytes(Charset.forName("US-ASCII"));
        this.factory = new KeyFactory();
    }

    @Test
    public void testCreateKey() throws Throwable
    {
        KeyInterface key = this.factory.createKey(this.encryptionSecret, this.authenticationSecret, "name", "description");

        Assert.assertEquals(key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(key.authenticationSecret(), this.authenticationSecret);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertEquals(key.description().get(), "description");
    }

    @Test
    public void testCreateKeyNoDescription() throws Throwable
    {
        KeyInterface key = this.factory.createKey(this.encryptionSecret, this.authenticationSecret, "name");

        Assert.assertEquals(key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(key.authenticationSecret(), this.authenticationSecret);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertFalse(key.description().isPresent());
    }

    @Test
    public void testCreateKeyNoNameOrDescription() throws Throwable
    {
        KeyInterface key = this.factory.createKey(this.encryptionSecret, this.authenticationSecret);

        Assert.assertEquals(key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(key.authenticationSecret(), this.authenticationSecret);
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
    final private byte[] encryptionSecret;
    final private byte[] authenticationSecret;
}
