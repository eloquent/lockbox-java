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
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Creates Bouncy Castle public key information instances.
 */
public class PublicKeyInformationFactory
    implements PublicKeyInformationFactoryInterface
{
    /**
     * Create a Bouncy Castle public key information instance.
     *
     * @param keyParameters The Bouncy Castle public key parameters.
     *
     * @return The Bouncy Castle public key information.
     * @throws IOException If the key cannot be converted.
     */
    public SubjectPublicKeyInfo create(final RSAKeyParameters keyParameters)
        throws IOException
    {
        return org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo(keyParameters);
    }
}
