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

public class DecryptionResultTest
{
    public DecryptionResultTest()
    {
        this.data = Bytes.asList("foobar".getBytes(Charset.forName("UTF-8")));
    }

    @Test
    public void testConstructor()
    {
        this.result = new DecryptionResult(DecryptionResultType.SUCCESS, this.data);

        Assert.assertSame(this.result.type(), DecryptionResultType.SUCCESS);
        Assert.assertTrue(this.result.isSuccessful());
        Assert.assertTrue(this.result.data().isPresent());
        Assert.assertEquals(this.result.data().get(), this.data);
    }

    @Test
    public void testConstructorDataOnly()
    {
        this.result = new DecryptionResult(this.data);

        Assert.assertSame(this.result.type(), DecryptionResultType.SUCCESS);
        Assert.assertTrue(this.result.isSuccessful());
        Assert.assertTrue(this.result.data().isPresent());
        Assert.assertEquals(this.result.data().get(), this.data);
    }

    @Test
    public void testConstructorTypeOnly()
    {
        this.result = new DecryptionResult(DecryptionResultType.SUCCESS);

        Assert.assertSame(this.result.type(), DecryptionResultType.SUCCESS);
        Assert.assertTrue(this.result.isSuccessful());
        Assert.assertFalse(this.result.data().isPresent());
    }

    @Test
    public void testSetData()
    {
        this.result = new DecryptionResult(DecryptionResultType.SUCCESS);
        this.result.setData(this.data);

        Assert.assertTrue(this.result.data().isPresent());
        Assert.assertEquals(this.result.data().get(), this.data);
    }

    final private List<Byte> data;
    private DecryptionResult result;
}
