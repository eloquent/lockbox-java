/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import java.math.BigInteger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * The interface implemented by Lockbox private keys.
 */
public interface PrivateKeyInterface extends KeyInterface
{
    /**
     * Get the modulus.
     *
     * @return The modulus.
     */
    public BigInteger modulus();

    /**
     * Get the public exponent.
     *
     * @return The public exponent.
     */
    public BigInteger publicExponent();

    /**
     * Get the private exponent.
     *
     * @return The private exponent.
     */
    public BigInteger privateExponent();

    /**
     * Get the first prime, or 'P'.
     *
     * @return The first prime.
     */
    public BigInteger prime1();

    /**
     * Get the second prime, or 'Q'.
     *
     * @return The second prime.
     */
    public BigInteger prime2();

    /**
     * Get the first prime exponent, or 'DP'.
     *
     * @return The first prime exponent.
     */
    public BigInteger primeExponent1();

    /**
     * Get the second prime exponent, or 'DQ'.
     *
     * @return The second prime exponent.
     */
    public BigInteger primeExponent2();

    /**
     * Get the coefficient, or 'QInv'.
     *
     * @return The coefficient.
     */
    public BigInteger coefficient();

    /**
     * Get the public key counterpart for this private key.
     *
     * @return The public key.
     */
    public PublicKey publicKey();

    /**
     * Get the Bouncy Castle RSA private key parameters.
     *
     * @return The Bouncy Castle RSA private key parameters.
     */
    public RSAPrivateCrtKeyParameters bcPrivateKeyParameters();

    /**
     * Get the Bouncy Castle RSA private key.
     *
     * @return The BouncyCastle RSA private key.
     */
    public RSAPrivateKey bcPrivateKey();

    /**
     * Get the Bouncy Castle private key information.
     *
     * @return The Bouncy Castle private key information.
     */
    public PrivateKeyInfo bcPrivateKeyInfo();

    /**
     * Get the JCE private key.
     *
     * @return The JCE private key.
     */
    public java.security.PrivateKey jcePrivateKey();

    /**
     * Get this key as a PEM formatted string.
     *
     * @return The PEM formatted key.
     */
    public String toPem();
}
