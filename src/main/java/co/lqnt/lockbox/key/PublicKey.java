/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.util.PemWriterFactory;
import co.lqnt.lockbox.util.PemWriterFactoryInterface;
import co.lqnt.lockbox.util.StringWriterFactory;
import co.lqnt.lockbox.util.StringWriterFactoryInterface;
import co.lqnt.lockbox.util.PublicKeyInformationFactory;
import co.lqnt.lockbox.util.PublicKeyInformationFactoryInterface;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Represents an Lockbox public key.
 */
public class PublicKey implements PublicKeyInterface
{
    /**
     * Construct a new Lockbox public key.
     *
     * @param modulus The modulus.
     * @param exponent The exponent.
     */
    public PublicKey(final BigInteger modulus, final BigInteger exponent)
    {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    /**
     * Get the modulus.
     *
     * @return The modulus.
     */
    public BigInteger modulus()
    {
        return this.modulus;
    }

    /**
     * Get the exponent.
     *
     * @return The exponent.
     */
    public BigInteger exponent()
    {
        return this.exponent;
    }

    /**
     * Get the size of this key in bits.
     *
     * @return The key size.
     */
    public int size()
    {
        return this.modulus().bitLength();
    }

    /**
     * Get the generic Bouncy Castle asymmetric key parameters.
     *
     * @return The generic Bouncy Castle asymmetric key parameters.
     */
    public AsymmetricKeyParameter bcKeyParameters()
    {
        return this.bcPublicKeyParameters();
    }

    /**
     * Get the Bouncy Castle RSA public key parameters.
     *
     * @return The Bouncy Castle RSA public key parameters.
     */
    public RSAKeyParameters bcPublicKeyParameters()
    {
        return new RSAKeyParameters(false, this.modulus(), this.exponent());
    }

    /**
     * Get the Bouncy Castle RSA public key.
     *
     * @return The BouncyCastle RSA public key.
     */
    public RSAPublicKey bcPublicKey()
    {
        return new RSAPublicKey(this.modulus(), this.exponent());
    }

    /**
     * Get the Bouncy Castle public key information.
     *
     * @return The Bouncy Castle public key information.
     */
    public SubjectPublicKeyInfo bcPublicKeyInfo()
    {
        return this.bcPublicKeyInfo(new PublicKeyInformationFactory());
    }

    /**
     * Get the Bouncy Castle public key information.
     *
     * @param factory The public key information factory to use.
     *
     * @return The Bouncy Castle public key information.
     */
    public SubjectPublicKeyInfo bcPublicKeyInfo(
        final PublicKeyInformationFactoryInterface factory
    ) {
        SubjectPublicKeyInfo keyInfo;
        try {
            keyInfo = factory.create(this.bcPublicKeyParameters());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return keyInfo;
    }

    /**
     * Get the JCE public key.
     *
     * @return The JCE public key.
     */
    public java.security.PublicKey jcePublicKey()
    {
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
        keyConverter.setProvider(new BouncyCastleProvider());

        return this.jcePublicKey(keyConverter);
    }

    /**
     * Get the JCE public key.
     *
     * @param keyConverter The key converter to use.
     *
     * @return The JCE public key.
     */
    public java.security.PublicKey jcePublicKey(
        final JcaPEMKeyConverter keyConverter
    ) {
        java.security.PublicKey jcePublicKey;
        try {
            jcePublicKey = keyConverter.getPublicKey(this.bcPublicKeyInfo());
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }

        return jcePublicKey;
    }

    /**
     * Get this key as a PEM formatted string.
     *
     * @return The PEM formatted key.
     */
    public String toPem()
    {
        return this.toPem(new StringWriterFactory(), new PemWriterFactory());
    }

    /**
     * Get this key as a PEM formatted string.
     *
     * @param stringWriterFactory The string writer factory to use.
     * @param pemWriterFactory    The PEM writer factory to use.
     *
     * @return The PEM formatted key.
     */
    public String toPem(
        final StringWriterFactoryInterface stringWriterFactory,
        final PemWriterFactoryInterface pemWriterFactory
    ) {
        StringWriter stringWriter = stringWriterFactory.create();
        PEMWriter pemWriter = pemWriterFactory.create(stringWriter);

        IOException error = null;
        try {
            pemWriter.writeObject(this.bcPublicKeyInfo());
        } catch (IOException e) {
            error = e;
        }

        try {
            pemWriter.close();
        } catch (IOException e) {
            if (null == error) {
                error = e;
            }
        }

        try {
            stringWriter.close();
        } catch (IOException e) {
            if (null == error) {
                error = e;
            }
        }

        if (null != error) {
            throw new RuntimeException(error);
        }

        return stringWriter.toString();
    }

    /**
     * Get this key as a PEM formatted string.
     *
     * @return The PEM formatted key.
     */
    @Override
    public String toString()
    {
        return this.toPem();
    }

    private BigInteger modulus;
    private BigInteger exponent;
}
