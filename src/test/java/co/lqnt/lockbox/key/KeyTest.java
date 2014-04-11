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
import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class KeyTest
{
    public KeyTest()
    {
        this.bytes16 = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        this.bytes24 = "123456789012345678901234".getBytes(Charset.forName("US-ASCII"));
        this.bytes28 = "1234567890123456789012345678".getBytes(Charset.forName("US-ASCII"));
        this.bytes32 = "12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII"));
        this.bytes48 = "123456789012345678901234567890123456789012345678".getBytes(Charset.forName("US-ASCII"));
        this.bytes64 = "1234567890123456789012345678901234567890123456789012345678901234"
            .getBytes(Charset.forName("US-ASCII"));
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
        byte[] encryptionSecret,
        int encryptionSecretBits,
        byte[] authenticationSecret,
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
        Assert.assertEquals(this.key.name(), "name");
        Assert.assertEquals(this.key.description(), "description");
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
        Assert.assertEquals(this.key.name(), "name");
        Assert.assertNull(this.key.description());
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
        Assert.assertNull(this.key.name());
        Assert.assertNull(this.key.description());
    }

    @Test(expectedExceptions = InvalidEncryptionSecretSizeException.class)
    public void testConstructorFailureInvalidEncryptionSecretSize() throws Throwable
    {
        new Key("foo".getBytes(Charset.forName("US-ASCII")), this.bytes28);
    }

    @Test(expectedExceptions = InvalidAuthenticationSecretSizeException.class)
    public void testConstructorFailureInvalidAuthenticationSecretSize() throws Throwable
    {
        new Key(this.bytes16, "foo".getBytes(Charset.forName("US-ASCII")));
    }

    private Key key;
    final private byte[] bytes16;
    final private byte[] bytes24;
    final private byte[] bytes28;
    final private byte[] bytes32;
    final private byte[] bytes48;
    final private byte[] bytes64;
}
