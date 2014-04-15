/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.stream;

import co.lqnt.lockbox.key.Key;
import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.List;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
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
        this.cipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.blockMac = new HMac(new SHA224Digest());
        this.finalMac = new HMac(new SHA224Digest());

        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);

        Mockito.when(this.randomSource.generate(16)).thenReturn(this.bytes16);
    }

    @BeforeMethod
    public void setUp()
    {
        this.out = new ByteArrayOutputStream();
        this.stream = new EncryptStream(
            this.out,
            this.key,
            this.randomSource,
            this.cipher,
            this.blockMac,
            this.finalMac
        );
    }

    @AfterMethod
    public void tearDown()
    {
        try {
            this.stream.close();
        } catch (IOException e) {}
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.stream.out(), this.out);
        Assert.assertSame(this.stream.key(), this.key);
        Assert.assertSame(this.stream.randomSource(), this.randomSource);
        Assert.assertSame(this.stream.cipher(), this.cipher);
        Assert.assertSame(this.stream.blockMac(), this.blockMac);
        Assert.assertSame(this.stream.finalMac(), this.finalMac);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.stream = new EncryptStream(this.out, this.key);

        Assert.assertSame(this.stream.randomSource().getClass(), SecureRandom.class);
        Assert.assertSame(this.stream.cipher().getClass(), PaddedBufferedBlockCipher.class);
        Assert.assertSame(this.stream.blockMac().getClass(), HMac.class);
        Assert.assertSame(this.stream.finalMac().getClass(), HMac.class);
    }

//    @Test
//    public void testStream() throws Throwable
//    {
//        this.stream.write("foo".getBytes(Charset.forName("UTF-8")), 0, 3);
//        this.stream.write("bar".getBytes(Charset.forName("UTF-8")), 0, 3);
//        this.stream.write("baz".getBytes(Charset.forName("UTF-8")), 0, 3);
//        this.stream.write("qux".getBytes(Charset.forName("UTF-8")), 0, 3);
//        this.stream.write("dooms".getBytes(Charset.forName("UTF-8")), 0, 3);
//        this.stream.write("plat".getBytes(Charset.forName("UTF-8")), 0, 3);
//        this.stream.close();
//
//        Assert.assertEquals(
//            BaseEncoding.base64Url().omitPadding().encode(this.out.toByteArray()),
//            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
//        );
//    }

    final private RandomSourceInterface randomSource;
    final private PaddedBufferedBlockCipher cipher;
    final private Mac blockMac;
    final private Mac finalMac;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
    final private KeyInterface key;
    private ByteArrayOutputStream out;
    private EncryptStream stream;
}
