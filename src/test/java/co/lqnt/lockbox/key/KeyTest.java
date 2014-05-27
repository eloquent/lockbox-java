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
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class KeyTest
{
    public KeyTest()
    {
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
    }

    @DataProvider(name = "validEncryptSecretData")
    public Object[][] validEncryptSecretData()
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

    @Test(dataProvider = "validEncryptSecretData")
    public void testConstructor(
        final List<Byte> encryptSecret,
        final int encryptSecretBits,
        final List<Byte> authSecret,
        final int authSecretBits
    ) throws Throwable
    {
        this.key = new Key(encryptSecret, authSecret, "name", "description");

        Assert.assertEquals(this.key.encryptSecret(), encryptSecret);
        Assert.assertEquals(this.key.encryptSecretBytes(), encryptSecretBits / 8);
        Assert.assertEquals(this.key.encryptSecretBits(), encryptSecretBits);
        Assert.assertEquals(this.key.authSecret(), authSecret);
        Assert.assertEquals(this.key.authSecretBytes(), authSecretBits / 8);
        Assert.assertEquals(this.key.authSecretBits(), authSecretBits);
        Assert.assertEquals(this.key.name().get(), "name");
        Assert.assertEquals(this.key.description().get(), "description");
    }

    @Test
    public void testConstructorNoDescription() throws Throwable
    {
        this.key = new Key(this.bytes16, this.bytes28, "name");

        Assert.assertEquals(this.key.encryptSecret(), this.bytes16);
        Assert.assertEquals(this.key.encryptSecretBytes(), 16);
        Assert.assertEquals(this.key.encryptSecretBits(), 128);
        Assert.assertEquals(this.key.authSecret(), this.bytes28);
        Assert.assertEquals(this.key.authSecretBytes(), 28);
        Assert.assertEquals(this.key.authSecretBits(), 224);
        Assert.assertEquals(this.key.name().get(), "name");
        Assert.assertFalse(this.key.description().isPresent());
    }

    @Test
    public void testConstructorNoNameOrDescription() throws Throwable
    {
        this.key = new Key(this.bytes16, this.bytes28);

        Assert.assertEquals(this.key.encryptSecret(), this.bytes16);
        Assert.assertEquals(this.key.encryptSecretBytes(), 16);
        Assert.assertEquals(this.key.encryptSecretBits(), 128);
        Assert.assertEquals(this.key.authSecret(), this.bytes28);
        Assert.assertEquals(this.key.authSecretBytes(), 28);
        Assert.assertEquals(this.key.authSecretBits(), 224);
        Assert.assertFalse(this.key.name().isPresent());
        Assert.assertFalse(this.key.description().isPresent());
    }

    @Test(expectedExceptions = InvalidEncryptSecretSizeException.class)
    public void testConstructorFailureInvalidEncryptSecretSize() throws Throwable
    {
        new Key(Bytes.asList("foo".getBytes(Charset.forName("US-ASCII"))), this.bytes28);
    }

    @Test(expectedExceptions = InvalidAuthSecretSizeException.class)
    public void testConstructorFailureInvalidAuthSecretSize() throws Throwable
    {
        new Key(this.bytes16, Bytes.asList("foo".getBytes(Charset.forName("US-ASCII"))));
    }

    @Test
    public void testErase() throws Throwable
    {
        this.key = new Key(this.bytes16, this.bytes28, "name", "description");
        this.key.erase();
        List<Byte> expectedEncryptSecret =
            Bytes.asList("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(Charset.forName("US-ASCII")));
        List<Byte> expectedAuthSecret =
            Bytes.asList(
                "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(Charset.forName("US-ASCII"))
            );

        Assert.assertEquals(this.key.encryptSecret(), expectedEncryptSecret);
        Assert.assertEquals(this.key.encryptSecretBytes(), 16);
        Assert.assertEquals(this.key.encryptSecretBits(), 128);
        Assert.assertEquals(this.key.authSecret(), expectedAuthSecret);
        Assert.assertEquals(this.key.authSecretBytes(), 28);
        Assert.assertEquals(this.key.authSecretBits(), 224);
        Assert.assertFalse(this.key.name().isPresent());
        Assert.assertFalse(this.key.description().isPresent());
    }

    private Key key;
    final private List<Byte> bytes16;
    final private List<Byte> bytes24;
    final private List<Byte> bytes28;
    final private List<Byte> bytes32;
    final private List<Byte> bytes48;
    final private List<Byte> bytes64;
}
