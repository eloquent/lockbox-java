/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util;

import java.io.IOException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Creates Bouncy Castle private key information instances.
 */
public class PrivateKeyInformationFactory
    implements PrivateKeyInformationFactoryInterface
{
    /**
     * Create a Bouncy Castle private key information instance.
     *
     * @param keyParameters The Bouncy Castle private key parameters.
     *
     * @return The Bouncy Castle private key information.
     * @throws IOException If the key cannot be converted.
     */
    public PrivateKeyInfo create(final RSAPrivateCrtKeyParameters keyParameters)
        throws IOException
    {
        return org.bouncycastle.crypto.util.PrivateKeyInfoFactory
            .createPrivateKeyInfo(keyParameters);
    }
}
