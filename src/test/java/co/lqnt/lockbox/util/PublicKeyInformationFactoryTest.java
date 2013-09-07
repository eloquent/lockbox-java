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
import co.lqnt.lockbox.key.PublicKey;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.testng.annotations.Test;

public class PublicKeyInformationFactoryTest
{
    @Test
    public void testFactory() throws Throwable
    {
        KeyFactory keyFactory = new KeyFactory();
        PublicKey key = keyFactory.createPublicKey(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.public.pem")
        );
        PublicKeyInformationFactory factory = new PublicKeyInformationFactory();
        RSAKeyParameters parameters = key.bcPublicKeyParameters();

        factory.create(parameters);
    }
}
