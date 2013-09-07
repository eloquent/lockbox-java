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
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * The interface implemented by Bouncy Castle public key parameter factories.
 */
public interface BcKeyParametersFactoryInterface
{
    /**
     * Create a new Bouncy Castle private key parameters instance.
     *
     * @param keyInformation The Bouncy Castle private key information.
     *
     * @return The Bouncy Castle private key parameters.
     * @throws IOException If the key conversion fails.
     */
    public AsymmetricKeyParameter createPrivateKeyParameters(
        final PrivateKeyInfo keyInformation
    )
        throws IOException;

    /**
     * Create a new Bouncy Castle public key parameters instance.
     *
     * @param keyInformation The Bouncy Castle public key information.
     *
     * @return The Bouncy Castle public key parameters.
     * @throws IOException If the key conversion fails.
     */
    public AsymmetricKeyParameter createPublicKeyParameters(
        final SubjectPublicKeyInfo keyInformation
    )
        throws IOException;
}
