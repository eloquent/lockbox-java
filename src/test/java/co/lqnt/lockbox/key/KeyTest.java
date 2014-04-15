/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidAuthenticationSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidEncryptionSecretSizeException;
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

    @DataProvider(name = "validEncryptionSecretData")
    public Object[][] validEncryptionSecretData()
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

    @Test(dataProvider = "validEncryptionSecretData")
    public void testConstructor(
        List<Byte> encryptionSecret,
        int encryptionSecretBits,
        List<Byte> authenticationSecret,
        int authenticationSecretBits
    ) throws Throwable
    {
        this.key = new Key(encryptionSecret, authenticationSecret, "name", "description");

        Assert.assertEquals(this.key.encryptionSecret(), encryptionSecret);
        Assert.assertEquals(this.key.encryptionSecretBytes(), encryptionSecretBits / 8);
        Assert.assertEquals(this.key.encryptionSecretBits(), encryptionSecretBits);
        Assert.assertEquals(this.key.authenticationSecret(), authenticationSecret);
        Assert.assertEquals(this.key.authenticationSecretBytes(), authenticationSecretBits / 8);
        Assert.assertEquals(this.key.authenticationSecretBits(), authenticationSecretBits);
        Assert.assertEquals(this.key.name().get(), "name");
        Assert.assertEquals(this.key.description().get(), "description");
    }

    @Test
    public void testConstructorNoDescription() throws Throwable
    {
        this.key = new Key(this.bytes16, this.bytes28, "name");

        Assert.assertEquals(this.key.encryptionSecret(), this.bytes16);
        Assert.assertEquals(this.key.encryptionSecretBytes(), 16);
        Assert.assertEquals(this.key.encryptionSecretBits(), 128);
        Assert.assertEquals(this.key.authenticationSecret(), this.bytes28);
        Assert.assertEquals(this.key.authenticationSecretBytes(), 28);
        Assert.assertEquals(this.key.authenticationSecretBits(), 224);
        Assert.assertEquals(this.key.name().get(), "name");
        Assert.assertFalse(this.key.description().isPresent());
    }

    @Test
    public void testConstructorNoNameOrDescription() throws Throwable
    {
        this.key = new Key(this.bytes16, this.bytes28);

        Assert.assertEquals(this.key.encryptionSecret(), this.bytes16);
        Assert.assertEquals(this.key.encryptionSecretBytes(), 16);
        Assert.assertEquals(this.key.encryptionSecretBits(), 128);
        Assert.assertEquals(this.key.authenticationSecret(), this.bytes28);
        Assert.assertEquals(this.key.authenticationSecretBytes(), 28);
        Assert.assertEquals(this.key.authenticationSecretBits(), 224);
        Assert.assertFalse(this.key.name().isPresent());
        Assert.assertFalse(this.key.description().isPresent());
    }

    @Test(expectedExceptions = InvalidEncryptionSecretSizeException.class)
    public void testConstructorFailureInvalidEncryptionSecretSize() throws Throwable
    {
        new Key(Bytes.asList("foo".getBytes(Charset.forName("US-ASCII"))), this.bytes28);
    }

    @Test(expectedExceptions = InvalidAuthenticationSecretSizeException.class)
    public void testConstructorFailureInvalidAuthenticationSecretSize() throws Throwable
    {
        new Key(this.bytes16, Bytes.asList("foo".getBytes(Charset.forName("US-ASCII"))));
    }

    private Key key;
    final private List<Byte> bytes16;
    final private List<Byte> bytes24;
    final private List<Byte> bytes28;
    final private List<Byte> bytes32;
    final private List<Byte> bytes48;
    final private List<Byte> bytes64;
}
