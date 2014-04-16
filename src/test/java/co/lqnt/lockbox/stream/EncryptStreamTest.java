/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.stream;

import co.lqnt.lockbox.cipher.LockboxKeyCipher;
import co.lqnt.lockbox.key.Key;
import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.List;
import org.bouncycastle.util.Arrays;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class EncryptStreamTest
{
    public EncryptStreamTest() throws Throwable
    {
        this.randomSource = Mockito.mock(RandomSourceInterface.class);
        this.cipher = new LockboxKeyCipher();

        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);

        Mockito.when(this.randomSource.generate(16)).thenReturn(this.bytes16);
    }

    @BeforeMethod
    public void setUp()
    {
        this.out = new ByteArrayOutputStream();
        this.stream = new EncryptStream(this.out, this.key, this.randomSource, this.cipher);
    }

    @AfterMethod
    public void tearDown()
    {
        try {
            this.stream.close();
        } catch (Throwable e) {}
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.stream.out(), this.out);
        Assert.assertSame(this.stream.key(), this.key);
        Assert.assertSame(this.stream.randomSource(), this.randomSource);
        Assert.assertSame(this.stream.cipher(), this.cipher);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.stream = new EncryptStream(this.out, this.key);

        Assert.assertSame(this.stream.randomSource().getClass(), SecureRandom.class);
        Assert.assertSame(this.stream.cipher().getClass(), LockboxKeyCipher.class);
    }

    @Test
    public void testStream() throws Throwable
    {
        byte[] input = "foobarbazquxdoomsplat".getBytes(Charset.forName("UTF-8"));
        this.stream.write(input, 0, 3);
        this.stream.write(input, 3, 3);
        this.stream.write(input, 6, 3);
        this.stream.write(input, 9, 3);
        this.stream.write(input, 12, 5);
        this.stream.write(input, 17, 4);
        this.stream.close();

        EncryptStreamTest.assertCiphertext(
            this.out.toByteArray(),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
        );
    }

    @Test
    public void testStreamWithExactBlockSizes() throws Throwable
    {
        byte[] input = "foobarbazquxdoomfoobarbazquxdoom".getBytes(Charset.forName("UTF-8"));
        this.stream.write(input, 0, 16);
        this.stream.write(input, 16, 16);
        this.stream.close();

        EncryptStreamTest.assertCiphertext(
            this.out.toByteArray(),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu0_Bk3cPXHsLggdoFLPnlwR29pd_lX36Diz3sv2v6sIsAmdbSuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g"
        );
    }

    static private void assertCiphertext(byte[] actual, String expected)
    {
        BaseEncoding encoding = BaseEncoding.base64Url().omitPadding();

        byte[] expectedBytes = encoding.decode(expected);
        String expectedVersion = encoding.encode(Arrays.copyOfRange(expectedBytes, 0, 1));
        String expectedType = encoding.encode(Arrays.copyOfRange(expectedBytes, 1, 2));
        String expectedIv = encoding.encode(Arrays.copyOfRange(expectedBytes, 2, 18));
        String expectedData = encoding.encode(Arrays.copyOfRange(expectedBytes, 18, expectedBytes.length - 28));
        String expectedMac = encoding
            .encode(Arrays.copyOfRange(expectedBytes, expectedBytes.length - 28, expectedBytes.length));

        String actualVersion = encoding.encode(Arrays.copyOfRange(actual, 0, 1));
        String actualType = encoding.encode(Arrays.copyOfRange(actual, 1, 2));
        String actualIv = encoding.encode(Arrays.copyOfRange(actual, 2, 18));
        String actualData = encoding.encode(Arrays.copyOfRange(actual, 18, actual.length - 28));
        String actualMac = encoding.encode(Arrays.copyOfRange(actual, actual.length - 28, actual.length));

        Assert.assertEquals(actualVersion, expectedVersion);
        Assert.assertEquals(actualType, expectedType);
        Assert.assertEquals(actualIv, expectedIv);
        Assert.assertEquals(actualData, expectedData);
        Assert.assertEquals(actualMac, expectedMac);
        Assert.assertEquals(encoding.encode(actual), expected);
    }

    final private RandomSourceInterface randomSource;
    final private LockboxKeyCipher cipher;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
    final private KeyInterface key;
    private ByteArrayOutputStream out;
    private EncryptStream stream;
}
