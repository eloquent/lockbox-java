/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidAuthSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidEncryptSecretSizeException;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class KeyGeneratorTest
{
    public KeyGeneratorTest()
    {
        this.randomSource = Mockito.mock(RandomSourceInterface.class);

        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes24 = Bytes.asList("123456789012345678901234".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.bytes32 = Bytes.asList("12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII")));
        this.bytes48 = Bytes.asList(
            "123456789012345678901234567890123456789012345678".getBytes(Charset.forName("US-ASCII"))
        );
        this.bytes64 = Bytes.asList(
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(Charset.forName("US-ASCII"))
        );

        Mockito.when(this.randomSource.generate(16)).thenReturn(this.bytes16);
        Mockito.when(this.randomSource.generate(24)).thenReturn(this.bytes24);
        Mockito.when(this.randomSource.generate(28)).thenReturn(this.bytes28);
        Mockito.when(this.randomSource.generate(32)).thenReturn(this.bytes32);
        Mockito.when(this.randomSource.generate(48)).thenReturn(this.bytes48);
        Mockito.when(this.randomSource.generate(64)).thenReturn(this.bytes64);
    }

    @BeforeMethod
    public void setUp()
    {
        this.factory = new KeyFactory();
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

    @DataProvider(name = "generatedKeyData")
    public Object[][] generatedKeyData()
    {
        return new Object[][]{
            {this.bytes32, 256, this.bytes64, 512},
            {this.bytes32, 256, this.bytes48, 384},
            {this.bytes32, 256, this.bytes32, 256},
            {this.bytes32, 256, this.bytes28, 224},
            {this.bytes24, 192, this.bytes64, 512},
            {this.bytes24, 192, this.bytes48, 384},
            {this.bytes24, 192, this.bytes32, 256},
            {this.bytes24, 192, this.bytes28, 224},
            {this.bytes16, 128, this.bytes64, 512},
            {this.bytes16, 128, this.bytes48, 384},
            {this.bytes16, 128, this.bytes32, 256},
            {this.bytes16, 128, this.bytes28, 224},
        };
    }

    @Test(dataProvider = "generatedKeyData")
    public void testGenerateKey(
        final List<Byte> encryptionSecret,
        final int encryptionSecretBits,
        final List<Byte> authenticationSecret,
        final int authenticationSecretBits
    ) throws Throwable
    {
        KeyInterface key = this.generator.generateKey(
            "name",
            "description",
            encryptionSecretBits,
            authenticationSecretBits
        );

        Assert.assertEquals(key.encryptSecret(), encryptionSecret);
        Assert.assertEquals(key.authSecret(), authenticationSecret);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertEquals(key.description().get(), "description");
    }

    @Test
    public void testGenerateKeyDefaultSizes()
    {
        KeyInterface key = this.generator.generateKey("name", "description");

        Assert.assertEquals(key.encryptSecret(), this.bytes32);
        Assert.assertEquals(key.authSecret(), this.bytes32);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertEquals(key.description().get(), "description");
    }

    @Test
    public void testGenerateKeyDefaultSizesNoDescription()
    {
        KeyInterface key = this.generator.generateKey("name");

        Assert.assertEquals(key.encryptSecret(), this.bytes32);
        Assert.assertEquals(key.authSecret(), this.bytes32);
        Assert.assertEquals(key.name().get(), "name");
        Assert.assertFalse(key.description().isPresent());
    }

    @Test
    public void testGenerateKeyDefaultSizesNoDescriptionOrName()
    {
        KeyInterface key = this.generator.generateKey();

        Assert.assertEquals(key.encryptSecret(), this.bytes32);
        Assert.assertEquals(key.authSecret(), this.bytes32);
        Assert.assertFalse(key.name().isPresent());
        Assert.assertFalse(key.description().isPresent());
    }

    @Test
    public void testGenerateKeySizesOnly() throws Throwable
    {
        KeyInterface key = this.generator.generateKey(128, 224);

        Assert.assertEquals(key.encryptSecret(), this.bytes16);
        Assert.assertEquals(key.authSecret(), this.bytes28);
        Assert.assertFalse(key.name().isPresent());
        Assert.assertFalse(key.description().isPresent());
    }

    @Test(expectedExceptions = InvalidEncryptSecretSizeException.class)
    public void testGenerateKeyFailureEncryptionKeySize() throws Throwable
    {
        this.generator.generateKey(111, 224);
    }

    @Test(expectedExceptions = InvalidAuthSecretSizeException.class)
    public void testGenerateKeyFailureAuthenticationKeySize() throws Throwable
    {
        this.generator.generateKey(128, 111);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGenerateKeyDefaultsFailureEncryptionKeySize() throws Throwable
    {
        this.factory = Mockito.mock(KeyFactoryInterface.class);
        this.generator = new KeyGenerator(this.factory, this.randomSource);
        Mockito.when(this.factory.createKey(this.bytes32, this.bytes32, null, null))
            .thenThrow(new InvalidEncryptSecretSizeException(256));

        this.generator.generateKey();
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGenerateKeyDefaultsFailureAuthenticationKeySize() throws Throwable
    {
        this.factory = Mockito.mock(KeyFactoryInterface.class);
        this.generator = new KeyGenerator(this.factory, this.randomSource);
        Mockito.when(this.factory.createKey(this.bytes32, this.bytes32, null, null))
            .thenThrow(new InvalidAuthSecretSizeException(256));

        this.generator.generateKey();
    }

    @Test
    public void testInstance()
    {
        KeyGenerator instance = KeyGenerator.instance();

        Assert.assertSame(KeyGenerator.instance(), instance);
    }

    private KeyGenerator generator;
    private KeyFactoryInterface factory;
    final private RandomSourceInterface randomSource;
    final private List<Byte> bytes16;
    final private List<Byte> bytes24;
    final private List<Byte> bytes28;
    final private List<Byte> bytes32;
    final private List<Byte> bytes48;
    final private List<Byte> bytes64;
}
