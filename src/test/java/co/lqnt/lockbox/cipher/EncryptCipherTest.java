/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.exception.CipherFinalizedException;
import co.lqnt.lockbox.cipher.exception.CipherNotInitializedException;
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
        this.bytes32 = Bytes.asList("12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);
        this.keyAlternate = new Key(this.bytes32, this.bytes32);
        this.parameters = new EncryptParameters(this.key, this.bytes16);
        this.parametersDefaults = new EncryptParameters(this.key);
        this.parametersInvalid = Mockito.mock(CipherParametersInterface.class);
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
        this.cipher.initialize(this.parametersInvalid);
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

    @Test
    public void testCipherWithKeyOnlyParameters()
    {
        this.cipher.initialize(this.parametersDefaults);
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

    @Test
    public void testCipherWithKeyOnly()
    {
        this.cipher.initialize(this.key);
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

    @Test
    public void testCipherEmpty()
    {
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(0)];
        this.cipher.finalize(output, 0);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2BsV8no6a9yLYUT6rbu2PdNC4LItQ9m-F9dQ65M-pun4OnZkLrHT8zDDw0sE4Dg"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testCipherByteByByte()
    {
        this.cipher.initialize(this.parameters);
        byte[] input = "foobarbazquxdoomsplat".getBytes(Charset.forName("US-ASCII"));
        byte[] output = new byte[this.cipher.finalOutputSize(input.length)];
        int outputOffset = 0;
        for (int i = 0; i < input.length; i++) {
            outputOffset += this.cipher.process(input[i], output, outputOffset);
        }
        this.cipher.finalize(output, outputOffset);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testCipherWithSmallPackets()
    {
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(21)];
        int outputOffset = 0;
        outputOffset += this.cipher.process("foo".getBytes(Charset.forName("US-ASCII")), 0, 3, output, outputOffset);
        outputOffset += this.cipher.process("bar".getBytes(Charset.forName("US-ASCII")), 0, 3, output, outputOffset);
        outputOffset += this.cipher.process("baz".getBytes(Charset.forName("US-ASCII")), 0, 3, output, outputOffset);
        outputOffset += this.cipher.process("qux".getBytes(Charset.forName("US-ASCII")), 0, 3, output, outputOffset);
        outputOffset += this.cipher.process("dooms".getBytes(Charset.forName("US-ASCII")), 0, 5, output, outputOffset);
        outputOffset += this.cipher.process("plat".getBytes(Charset.forName("US-ASCII")), 0, 4, output, outputOffset);
        this.cipher.finalize(output, outputOffset);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testCipherBlockByBlock()
    {
        this.cipher.initialize(this.parameters);
        byte[] input = "foobarbazquxdoom".getBytes(Charset.forName("US-ASCII"));
        byte[] output = new byte[this.cipher.finalOutputSize(input.length * 2)];
        int outputOffset = 0;
        outputOffset += this.cipher.process(input, 0, input.length, output, outputOffset);
        outputOffset += this.cipher.process(input, 0, input.length, output, outputOffset);
        this.cipher.finalize(output, outputOffset);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu0_Bk3cPXHsLggdoFLPnlwR29pd_lX36Diz3sv2v6sIsAmdbSuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testCipherBlockByBlockProcessThenFinalize()
    {
        this.cipher.initialize(this.parameters);
        byte[] input = "foobarbazquxdoom".getBytes(Charset.forName("US-ASCII"));
        byte[] output = new byte[this.cipher.finalOutputSize(input.length * 2)];
        int outputOffset = 0;
        outputOffset += this.cipher.process(input, 0, input.length, output, outputOffset);
        this.cipher.finalize(input, 0, input.length, output, outputOffset);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARu0_Bk3cPXHsLggdoFLPnlwR29pd_lX36Diz3sv2v6sIsAmdbSuDnDnVctQhnxXOgECTCSb8G-xnE_kmnhWk432g"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testInitializeAfterUse()
    {
        byte[] input = "foobarbazquxdoomsplat".getBytes(Charset.forName("US-ASCII"));
        this.cipher.initialize(this.keyAlternate);
        byte[] output = new byte[this.cipher.finalOutputSize(input.length)];
        this.cipher.process(input, 0, input.length, output, 0);
        this.cipher.initialize(this.parameters);
        output = new byte[this.cipher.finalOutputSize(input.length)];
        this.cipher.finalize(input, 0, input.length, output, 0);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testResetAfterUse()
    {
        this.cipher.reset();
        byte[] input = "foobarbazquxdoomsplat".getBytes(Charset.forName("US-ASCII"));
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(input.length)];
        this.cipher.process(input, 0, input.length, output, 0);
        this.cipher.reset();
        this.cipher.finalize(input, 0, input.length, output, 0);
        
        Assert.assertEquals(
            this.base64Url.encode(output),
            "AQExMjM0NTY3ODkwMTIzNDU2T5xLPdYzBeLJW8xyiDdJlARuJu2o4QnrWgwEVekzq_uQOat_qDHhGSRzIGUQo-U-BdePDs_-jLRS8U4RCmUjyg"
        );
        Assert.assertTrue(this.cipher.isFinalized());
        Assert.assertTrue(this.cipher.result().isPresent());
        Assert.assertSame(this.cipher.result().get().type(), CipherResultType.SUCCESS);
    }

    @Test(expectedExceptions = CipherNotInitializedException.class)
    public void testProcessOutputSizeFailureNotInitialized()
    {
        this.cipher.processOutputSize(0);
    }

    @Test(expectedExceptions = CipherFinalizedException.class)
    public void testProcessOutputSizeFailureFinalized()
    {
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(0)];
        this.cipher.finalize(output, 0);
        
        this.cipher.processOutputSize(0);
    }

    @Test(expectedExceptions = CipherNotInitializedException.class)
    public void testProcessFailureNotInitialized()
    {
        byte[] input = new byte[0];
        byte[] output = new byte[0];
        
        this.cipher.process(input, 0, 0, output, 0);
    }

    @Test(expectedExceptions = CipherFinalizedException.class)
    public void testProcessFailureFinalized()
    {
        byte[] input = new byte[0];
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(0)];
        this.cipher.finalize(output, 0);
        
        this.cipher.process(input, 0, 0, output, 0);
    }

    @Test(expectedExceptions = CipherNotInitializedException.class)
    public void testFinalOutputSizeFailureNotInitialized()
    {
        this.cipher.finalOutputSize(0);
    }

    @Test(expectedExceptions = CipherFinalizedException.class)
    public void testFinalOutputSizeFailureFinalized()
    {
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(0)];
        this.cipher.finalize(output, 0);
        
        this.cipher.finalOutputSize(0);
    }

    @Test(expectedExceptions = CipherNotInitializedException.class)
    public void testFinalizeFailureNotInitialized()
    {
        byte[] output = new byte[0];
        
        this.cipher.finalize(output, 0);
    }

    @Test(expectedExceptions = CipherFinalizedException.class)
    public void testFinalizeFailureFinalized()
    {
        this.cipher.initialize(this.parameters);
        byte[] output = new byte[this.cipher.finalOutputSize(0)];
        this.cipher.finalize(output, 0);
        
        this.cipher.finalize(output, 0);
    }

    private EncryptCipher cipher;
    final private RandomSourceInterface randomSource;
    final private CipherResultFactoryInterface resultFactory;
    final private List<Byte> bytes16;
    final private List<Byte> bytes28;
    final private List<Byte> bytes32;
    final private KeyInterface key;
    final private KeyInterface keyAlternate;
    final private CipherParametersInterface parameters;
    final private CipherParametersInterface parametersDefaults;
    final private CipherParametersInterface parametersInvalid;
    final private BaseEncoding base64Url;
}
