/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.exception.UnsupportedCipherParametersException;
import co.lqnt.lockbox.cipher.parameters.CipherParametersInterface;
import co.lqnt.lockbox.cipher.parameters.EncryptParameters;
import co.lqnt.lockbox.cipher.result.CipherResultType;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactory;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactoryInterface;
import co.lqnt.lockbox.key.Key;
import co.lqnt.lockbox.key.KeyInterface;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class EncryptCipherTest
{
    public EncryptCipherTest() throws Throwable
    {
        this.randomSource = Mockito.mock(RandomSourceInterface.class);
        this.resultFactory = new CipherResultFactory();
        
        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);
        this.parameters = new EncryptParameters(this.key, this.bytes16);
        this.parametersDefaults = new EncryptParameters(this.key);
        this.base64Url = BaseEncoding.base64Url().omitPadding();
        
        Mockito.when(this.randomSource.generate(16)).thenReturn(this.bytes16);
    }

    @BeforeMethod
    public void setUp()
    {
        this.cipher = new EncryptCipher(this.randomSource, this.resultFactory);
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.cipher.randomSource(), this.randomSource);
        Assert.assertSame(this.cipher.resultFactory(), this.resultFactory);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.cipher = new EncryptCipher();
        
        Assert.assertSame(this.cipher.randomSource(), SecureRandom.instance());
        Assert.assertSame(this.cipher.resultFactory(), CipherResultFactory.instance());
    }

    @Test
    public void testIsInitialized()
    {
        Assert.assertFalse(this.cipher.isInitialized());
        
        this.cipher.initialize(this.parameters);
        
        Assert.assertTrue(this.cipher.isInitialized());
    }

    @Test(expectedExceptions = UnsupportedCipherParametersException.class)
    public void testInitializeUnsupported()
    {
        CipherParametersInterface parameters = Mockito.mock(CipherParametersInterface.class);
        
        this.cipher.initialize(parameters);
    }

    @Test
    public void testCipherWithKeyAndIvParameters()
    {
        this.cipher.initialize(this.parameters);
        byte[] input = "foobarbazquxdoomsplat".getBytes(Charset.forName("US-ASCII"));
        byte[] output = new byte[this.cipher.finalOutputSize(input.length)];
        this.cipher.finalize(input, 0, input.length, output, 0);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    private EncryptCipher cipher;
    final private RandomSourceInterface randomSource;
    final private CipherResultFactoryInterface resultFactory;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
    final private KeyInterface key;
    final private CipherParametersInterface parameters;
    final private CipherParametersInterface parametersDefaults;
    final private BaseEncoding base64Url;
}
