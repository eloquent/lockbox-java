/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result;

import com.google.common.primitives.Bytes;
import java.nio.charset.Charset;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CipherResultTest
{
    public CipherResultTest()
    {
        this.data = Bytes.asList("foobar".getBytes(Charset.forName("UTF-8")));
    }

    @Test
    public void testConstructor()
    {
        this.result = new CipherResult(CipherResultType.SUCCESS, this.data);

        Assert.assertSame(this.result.type(), CipherResultType.SUCCESS);
        Assert.assertTrue(this.result.isSuccessful());
        Assert.assertTrue(this.result.data().isPresent());
        Assert.assertEquals(this.result.data().get(), this.data);
    }

    @Test
    public void testConstructorDataOnly()
    {
        this.result = new CipherResult(this.data);

        Assert.assertSame(this.result.type(), CipherResultType.SUCCESS);
        Assert.assertTrue(this.result.isSuccessful());
        Assert.assertTrue(this.result.data().isPresent());
        Assert.assertEquals(this.result.data().get(), this.data);
    }

    @Test
    public void testConstructorTypeOnly()
    {
        this.result = new CipherResult(CipherResultType.SUCCESS);

        Assert.assertSame(this.result.type(), CipherResultType.SUCCESS);
        Assert.assertTrue(this.result.isSuccessful());
        Assert.assertFalse(this.result.data().isPresent());
    }

    @Test
    public void testSetData()
    {
        this.result = new CipherResult(CipherResultType.SUCCESS);
        this.result.setData(this.data);

        Assert.assertTrue(this.result.data().isPresent());
        Assert.assertEquals(this.result.data().get(), this.data);
    }

    final private List<Byte> data;
    private CipherResult result;
}
