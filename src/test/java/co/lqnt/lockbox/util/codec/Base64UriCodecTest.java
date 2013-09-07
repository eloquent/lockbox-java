/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util.codec;

import co.lqnt.lockbox.util.codec.exception.DecodingFailedException;
import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class Base64UriCodecTest
{
    public Base64UriCodecTest()
    {
        this.codec = new Base64UriCodec();
    }

    @DataProvider(name = "codecData")
    public Object[][] codecData()
    {
        return new Object[][]{
            {"",       ""},
            {"f",      "Zg"},
            {"fo",     "Zm8"},
            {"foo",    "Zm9v"},
            {"foob",   "Zm9vYg"},
            {"fooba",  "Zm9vYmE"},
            {"foobar", "Zm9vYmFy"},
            {"~~~?_?", "fn5-P18_"}
        };
    }

    @Test(dataProvider = "codecData")
    public void testEncode(String data, String encoded)
    {
        Assert.assertEquals(
            new String(this.codec.encode(data.getBytes(Charset.forName("US-ASCII"))), Charset.forName("US-ASCII")),
            encoded
        );
    }

    @Test(dataProvider = "codecData")
    public void testEncodeString(String data, String encoded)
    {
        Assert.assertEquals(
            new String(this.codec.encode(data), Charset.forName("US-ASCII")),
            encoded
        );
    }

    @Test(dataProvider = "codecData")
    public void testDecode(String data, String encoded) throws Throwable
    {
        Assert.assertEquals(
            new String(this.codec.decode(encoded.getBytes(Charset.forName("US-ASCII"))), Charset.forName("US-ASCII")),
            data
        );
    }

    @Test(dataProvider = "codecData")
    public void testDecodeString(String data, String encoded) throws Throwable
    {
        Assert.assertEquals(
            new String(this.codec.decode(encoded), Charset.forName("US-ASCII")),
            data
        );
    }

    @DataProvider(name = "invalidData")
    public Object[][] invalidData()
    {
        return new Object[][]{
            {"Zgo="},
            {"fn5+P18/"}
        };
    }

    @Test(dataProvider = "invalidData", expectedExceptions = DecodingFailedException.class)
    public void testDecodeFailure(String encoded) throws Throwable
    {
        this.codec.decode(encoded.getBytes(Charset.forName("US-ASCII")));
    }

    @Test(dataProvider = "invalidData", expectedExceptions = DecodingFailedException.class)
    public void testDecodeFailureString(String encoded) throws Throwable
    {
        this.codec.decode(encoded);
    }

    private CodecInterface codec;
}
