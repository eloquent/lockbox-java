/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import java.nio.charset.Charset;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class KeyGeneratorTest
{
    public KeyGeneratorTest()
    {
        this.factory = new KeyFactory();
        this.randomSource = Mockito.mock(RandomSourceInterface.class);

        this.encryptionSecret = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        this.authenticationSecret = "1234567890123456789012345678".getBytes(Charset.forName("US-ASCII"));

        Mockito.when(this.randomSource.generate(16)).thenReturn(encryptionSecret);
        Mockito.when(this.randomSource.generate(28)).thenReturn(authenticationSecret);
    }

    @BeforeMethod
    public void setUp()
    {
        this.generator = new KeyGenerator(this.factory, this.randomSource);
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.generator.factory(), this.factory);
        Assert.assertSame(this.generator.randomSource(), this.randomSource);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.generator = new KeyGenerator();

        Assert.assertSame(this.generator.factory(), KeyFactory.instance());
        Assert.assertSame(this.generator.randomSource(), SecureRandom.instance());
    }

    @Test
    public void testGenerateKey() throws Throwable
    {
        KeyInterface key = this.generator.generateKey("name", "description", 128, 224);

        Assert.assertEquals(key.encryptionSecret(), this.encryptionSecret);
        Assert.assertEquals(key.authenticationSecret(), this.authenticationSecret);
        Assert.assertSame(key.name(), "name");
        Assert.assertSame(key.description(), "description");
    }

    @Test
    public void testInstance()
    {
        KeyGenerator instance = KeyGenerator.instance();

        Assert.assertSame(KeyGenerator.instance(), instance);
    }

    private KeyGenerator generator;
    final private KeyFactory factory;
    final private RandomSourceInterface randomSource;
    final private byte[] encryptionSecret;
    final private byte[] authenticationSecret;
}
