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

public class DecryptionResultTypeTest
{
    @Test
    public void testEnumeration()
    {
        DecryptionResultType[] expectedValues = new DecryptionResultType[7];
        expectedValues[0] = DecryptionResultType.SUCCESS;
        expectedValues[1] = DecryptionResultType.INVALID_SIZE;
        expectedValues[2] = DecryptionResultType.INVALID_ENCODING;
        expectedValues[3] = DecryptionResultType.INVALID_MAC;
        expectedValues[4] = DecryptionResultType.UNSUPPORTED_VERSION;
        expectedValues[5] = DecryptionResultType.UNSUPPORTED_TYPE;
        expectedValues[6] = DecryptionResultType.INVALID_PADDING;

        Assert.assertTrue(DecryptionResultType.SUCCESS.isSuccessful());
        Assert.assertFalse(DecryptionResultType.INVALID_SIZE.isSuccessful());
        Assert.assertFalse(DecryptionResultType.INVALID_ENCODING.isSuccessful());
        Assert.assertFalse(DecryptionResultType.INVALID_MAC.isSuccessful());
        Assert.assertFalse(DecryptionResultType.UNSUPPORTED_VERSION.isSuccessful());
        Assert.assertFalse(DecryptionResultType.UNSUPPORTED_TYPE.isSuccessful());
        Assert.assertFalse(DecryptionResultType.INVALID_PADDING.isSuccessful());
        Assert.assertSame(DecryptionResultType.valueOf("SUCCESS"), DecryptionResultType.SUCCESS);
        Assert.assertEquals(DecryptionResultType.values(), expectedValues);
    }
}
