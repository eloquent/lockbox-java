/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.cipher.result.factory;

import co.lqnt.lockbox.cipher.result.CipherResultInterface;
import co.lqnt.lockbox.cipher.result.CipherResultType;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CipherResultFactoryTest
{
    @Test
    public void testCreateResult() throws Throwable
    {
        CipherResultFactory factory = new CipherResultFactory();
        CipherResultInterface result = factory.createResult(CipherResultType.SUCCESS);

        Assert.assertEquals(result.type(), CipherResultType.SUCCESS);
    }

    @Test
    public void testInstance()
    {
        CipherResultFactory instance = CipherResultFactory.instance();

        Assert.assertSame(CipherResultFactory.instance(), instance);
    }
}
