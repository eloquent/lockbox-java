/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import co.lqnt.lockbox.key.KeyFactory;
import co.lqnt.lockbox.key.PrivateKey;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.testng.annotations.Test;

public class PrivateKeyInformationFactoryTest
{
    @Test
    public void testFactory() throws Throwable
    {
        KeyFactory keyFactory = new KeyFactory();
        PrivateKey key = keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.private.pem")
        );
        PrivateKeyInformationFactory factory = new PrivateKeyInformationFactory();
        RSAPrivateCrtKeyParameters parameters = key.bcPrivateKeyParameters();

        factory.create(parameters);
    }
}
