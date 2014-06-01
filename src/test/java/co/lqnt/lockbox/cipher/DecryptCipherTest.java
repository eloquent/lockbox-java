/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher;

import co.lqnt.lockbox.cipher.parameters.CipherParametersInterface;
import co.lqnt.lockbox.cipher.parameters.EncryptParameters;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactory;
import co.lqnt.lockbox.cipher.result.factory.CipherResultFactoryInterface;
import co.lqnt.lockbox.key.Key;
import co.lqnt.lockbox.key.KeyInterface;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class DecryptCipherTest
{
    public DecryptCipherTest() throws Throwable
    {
        this.resultFactory = new CipherResultFactory();

        this.bytes16 = Bytes.asList("1234567890123456".getBytes(Charset.forName("US-ASCII")));
        this.bytes24 = Bytes.asList("123456789012345678901234".getBytes(Charset.forName("US-ASCII")));
        this.bytes28 = Bytes.asList("1234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.bytes32 = Bytes.asList("12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII")));
        this.bytes48 = Bytes.asList("123456789012345678901234567890123456789012345678".getBytes(Charset.forName("US-ASCII")));
        this.bytes64 = Bytes.asList("1234567890123456789012345678901234567890123456789012345678901234".getBytes(Charset.forName("US-ASCII")));
        this.key = new Key(this.bytes16, this.bytes28);
        this.keyAlternate = new Key(this.bytes32, this.bytes32);
        this.parameters = new EncryptParameters(this.key, this.bytes16);
        this.parametersDefaults = new EncryptParameters(this.key);
        this.parametersInvalid = Mockito.mock(CipherParametersInterface.class);
        this.base64Url = BaseEncoding.base64Url().omitPadding();
    }

    @BeforeMethod
    public void setUp()
    {
        this.cipher = new DecryptCipher(this.resultFactory);
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.cipher.resultFactory(), this.resultFactory);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.cipher = new DecryptCipher();

        Assert.assertSame(this.cipher.resultFactory(), CipherResultFactory.instance());
    }

    private DecryptCipher cipher;
    final private CipherResultFactoryInterface resultFactory;
    final private List<Byte> bytes16;
    final private List<Byte> bytes24;
    final private List<Byte> bytes28;
    final private List<Byte> bytes32;
    final private List<Byte> bytes48;
    final private List<Byte> bytes64;
    final private KeyInterface key;
    final private KeyInterface keyAlternate;
    final private CipherParametersInterface parameters;
    final private CipherParametersInterface parametersDefaults;
    final private CipherParametersInterface parametersInvalid;
    final private BaseEncoding base64Url;
}
