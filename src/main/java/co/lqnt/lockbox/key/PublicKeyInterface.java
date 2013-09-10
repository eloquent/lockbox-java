/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * The interface implemented by Lockbox public keys.
 */
public interface PublicKeyInterface extends KeyInterface
{
    /**
     * Get the Bouncy Castle RSA public key parameters.
     *
     * @return The Bouncy Castle RSA public key parameters.
     */
    public RSAKeyParameters bcPublicKeyParameters();

    /**
     * Get the Bouncy Castle RSA public key.
     *
     * @return The BouncyCastle RSA public key.
     */
    public RSAPublicKey bcPublicKey();

    /**
     * Get the Bouncy Castle public key information.
     *
     * @return The Bouncy Castle public key information.
     */
    public SubjectPublicKeyInfo bcPublicKeyInfo();

    /**
     * Get the JCE public key.
     *
     * @return The JCE public key.
     */
    public java.security.PublicKey jcePublicKey();
}
