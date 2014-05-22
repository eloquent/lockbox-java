/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result;

import org.testng.Assert;
import org.testng.annotations.Test;

public class CipherResultTypeTest
{
    @Test
    public void testEnumeration()
    {
        CipherResultType[] expectedValues = new CipherResultType[8];
        expectedValues[0] = CipherResultType.SUCCESS;
        expectedValues[1] = CipherResultType.INVALID_SIZE;
        expectedValues[2] = CipherResultType.INVALID_ENCODING;
        expectedValues[3] = CipherResultType.INVALID_MAC;
        expectedValues[4] = CipherResultType.UNSUPPORTED_VERSION;
        expectedValues[5] = CipherResultType.UNSUPPORTED_TYPE;
        expectedValues[6] = CipherResultType.INVALID_PADDING;
        expectedValues[7] = CipherResultType.TOO_MANY_ITERATIONS;

        Assert.assertTrue(CipherResultType.SUCCESS.isSuccessful());
        Assert.assertFalse(CipherResultType.INVALID_SIZE.isSuccessful());
        Assert.assertFalse(CipherResultType.INVALID_ENCODING.isSuccessful());
        Assert.assertFalse(CipherResultType.INVALID_MAC.isSuccessful());
        Assert.assertFalse(CipherResultType.UNSUPPORTED_VERSION.isSuccessful());
        Assert.assertFalse(CipherResultType.UNSUPPORTED_TYPE.isSuccessful());
        Assert.assertFalse(CipherResultType.INVALID_PADDING.isSuccessful());
        Assert.assertFalse(CipherResultType.TOO_MANY_ITERATIONS.isSuccessful());
        Assert.assertSame(CipherResultType.valueOf("SUCCESS"), CipherResultType.SUCCESS);
        Assert.assertEquals(CipherResultType.values(), expectedValues);
    }
}
