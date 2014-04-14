/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import co.lqnt.lockbox.util.exception.ErasedDataException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ErasableDataTest
{
    @Test
    public void testCharArrayConstructor()
    {
        this.data = new ErasableData("foobar".toCharArray());

        Assert.assertEquals(new String(this.data.characters()), "foobar");
        Assert.assertEquals(new String(this.data.bytes(), Charset.forName("UTF-8")), "foobar");
        Assert.assertEquals(
            new String(this.data.bytes(Charset.forName("UTF-32")), Charset.forName("UTF-32")),
            "foobar"
        );
        Assert.assertNotEquals(this.data.toString(), "foobar");
        Assert.assertFalse(this.data.isErased());
    }

    @Test
    public void testByteArrayConstructor()
    {
        this.data = new ErasableData("foobar".getBytes());

        Assert.assertEquals(new String(this.data.characters()), "foobar");
        Assert.assertEquals(new String(this.data.bytes(), Charset.forName("UTF-8")), "foobar");
        Assert.assertEquals(
            new String(this.data.bytes(Charset.forName("UTF-32")), Charset.forName("UTF-32")),
            "foobar"
        );
        Assert.assertNotEquals(this.data.toString(), "foobar");
        Assert.assertFalse(this.data.isErased());
    }

    @Test
    public void testByteArrayWithEncodingConstructor()
    {
        this.data = new ErasableData("foobar".getBytes(Charset.forName("UTF-8")), Charset.forName("UTF-8"));

        Assert.assertEquals(new String(this.data.characters()), "foobar");
        Assert.assertEquals(new String(this.data.bytes(), Charset.forName("UTF-8")), "foobar");
        Assert.assertEquals(
            new String(this.data.bytes(Charset.forName("UTF-32")), Charset.forName("UTF-32")),
            "foobar"
        );
        Assert.assertNotEquals(this.data.toString(), "foobar");
        Assert.assertFalse(this.data.isErased());
    }

    @Test
    public void testStringConstructor()
    {
        this.data = new ErasableData("foobar");

        Assert.assertEquals(new String(this.data.characters()), "foobar");
        Assert.assertEquals(new String(this.data.bytes(), Charset.forName("UTF-8")), "foobar");
        Assert.assertEquals(
            new String(this.data.bytes(Charset.forName("UTF-32")), Charset.forName("UTF-32")),
            "foobar"
        );
        Assert.assertNotEquals(this.data.toString(), "foobar");
        Assert.assertFalse(this.data.isErased());
    }

    @Test
    public void testErase() throws Throwable
    {
        this.data = new ErasableData("foobar".toCharArray());
        this.data.erase();
        this.data.erase();
        Field dataField = this.data.getClass().getDeclaredField("data");
        dataField.setAccessible(true);

        Assert.assertTrue(this.data.isErased());
        Assert.assertEquals((char[]) dataField.get(this.data), "\u0000\u0000\u0000\u0000\u0000\u0000".toCharArray());
    }

    @Test(expectedExceptions = ErasedDataException.class)
    public void testCharactersAfterErase()
    {
        this.data = new ErasableData("foobar".toCharArray());
        this.data.erase();
        this.data.characters();
    }

    @Test(expectedExceptions = ErasedDataException.class)
    public void testBytesAfterErase()
    {
        this.data = new ErasableData("foobar".toCharArray());
        this.data.erase();
        this.data.bytes();
    }

    @Test(expectedExceptions = ErasedDataException.class)
    public void testBytesWithEncodingAfterErase()
    {
        this.data = new ErasableData("foobar".toCharArray());
        this.data.erase();
        this.data.bytes(Charset.forName("UTF-32"));
    }

    private ErasableData data;
}
