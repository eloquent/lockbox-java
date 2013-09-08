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
import co.lqnt.lockbox.util.PrivateKeyInformationFactory;
import co.lqnt.lockbox.util.PrivateKeyInformationFactoryInterface;
import co.lqnt.lockbox.util.StringWriterFactory;
import co.lqnt.lockbox.util.StringWriterFactoryInterface;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

/**
 * Represents a Lockbox private key.
 */
public class PrivateKey implements PrivateKeyInterface
{
    /**
     * Construct a new Lockbox private key.
     *
     * @param modulus         The modulus.
     * @param publicExponent  The public exponent.
     * @param privateExponent The private exponent.
     * @param prime1          The first prime, or 'P'.
     * @param prime2          The second prime, or 'Q'.
     * @param primeExponent1  The first prime exponent, or 'DP'.
     * @param primeExponent2  The first prime exponent, or 'DQ'.
     * @param coefficient     The coefficient, or 'QInv'.
     */
    public PrivateKey(
        final BigInteger modulus,
        final BigInteger publicExponent,
        final BigInteger privateExponent,
        final BigInteger prime1,
        final BigInteger prime2,
        final BigInteger primeExponent1,
        final BigInteger primeExponent2,
        final BigInteger coefficient
    ) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.primeExponent1 = primeExponent1;
        this.primeExponent2 = primeExponent2;
        this.coefficient = coefficient;
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
     * Get the public exponent.
     *
     * @return The public exponent.
     */
    public BigInteger publicExponent()
    {
        return this.publicExponent;
    }

    /**
     * Get the private exponent.
     *
     * @return The private exponent.
     */
    public BigInteger privateExponent()
    {
        return this.privateExponent;
    }

    /**
     * Get the first prime, or 'P'.
     *
     * @return The first prime.
     */
    public BigInteger prime1()
    {
        return this.prime1;
    }

    /**
     * Get the second prime, or 'Q'.
     *
     * @return The second prime.
     */
    public BigInteger prime2()
    {
        return this.prime2;
    }

    /**
     * Get the first prime exponent, or 'DP'.
     *
     * @return The first prime exponent.
     */
    public BigInteger primeExponent1()
    {
        return this.primeExponent1;
    }

    /**
     * Get the second prime exponent, or 'DQ'.
     *
     * @return The second prime exponent.
     */
    public BigInteger primeExponent2()
    {
        return this.primeExponent2;
    }

    /**
     * Get the coefficient, or 'QInv'.
     *
     * @return The coefficient.
     */
    public BigInteger coefficient()
    {
        return this.coefficient;
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
        return this.bcPrivateKeyParameters();
    }

    /**
     * Get the public key counterpart for this private key.
     *
     * @return The public key.
     */
    public PublicKey publicKey()
    {
        return new PublicKey(this.modulus(), this.publicExponent());
    }

    /**
     * Get the Bouncy Castle RSA private key parameters.
     *
     * @return The Bouncy Castle RSA private key parameters.
     */
    public RSAPrivateCrtKeyParameters bcPrivateKeyParameters()
    {
        return new RSAPrivateCrtKeyParameters(
            this.modulus(),
            this.publicExponent(),
            this.privateExponent(),
            this.prime1(),
            this.prime2(),
            this.primeExponent1(),
            this.primeExponent2(),
            this.coefficient()
        );
    }

    /**
     * Get the Bouncy Castle RSA private key.
     *
     * @return The BouncyCastle RSA private key.
     */
    public RSAPrivateKey bcPrivateKey()
    {
        return new RSAPrivateKey(
            this.modulus(),
            this.publicExponent(),
            this.privateExponent(),
            this.prime1(),
            this.prime2(),
            this.primeExponent1(),
            this.primeExponent2(),
            this.coefficient()
        );
    }

    /**
     * Get the Bouncy Castle private key information.
     *
     * @return The Bouncy Castle private key information.
     */
    public PrivateKeyInfo bcPrivateKeyInfo()
    {
        return this.bcPrivateKeyInfo(new PrivateKeyInformationFactory());
    }

    /**
     * Get the Bouncy Castle private key information.
     *
     * @param factory The private key information factory to use.
     *
     * @return The Bouncy Castle private key information.
     */
    public PrivateKeyInfo bcPrivateKeyInfo(
        final PrivateKeyInformationFactoryInterface factory
    ) {
        PrivateKeyInfo keyInfo;
        try {
            keyInfo = factory.create(this.bcPrivateKeyParameters());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return keyInfo;
    }

    /**
     * Get the JCE private key.
     *
     * @return The JCE private key.
     */
    public java.security.PrivateKey jcePrivateKey()
    {
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
        keyConverter.setProvider(new BouncyCastleProvider());

        return this.jcePrivateKey(keyConverter);
    }

    /**
     * Get the JCE private key.
     *
     * @param keyConverter The key converter to use.
     *
     * @return The JCE private key.
     */
    public java.security.PrivateKey jcePrivateKey(
        final JcaPEMKeyConverter keyConverter
    ) {
        java.security.PrivateKey jcePrivateKey;
        try {
            jcePrivateKey = keyConverter.getPrivateKey(this.bcPrivateKeyInfo());
        } catch (PEMException e) {
            throw new RuntimeException(e);
        }

        return jcePrivateKey;
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
     * @param password A password to encrypt the PEM data with.
     *
     * @return The PEM formatted key.
     */
    public String toPem(final String password)
    {
        JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder(
            "DES-EDE3-CBC"
        );
        encryptorBuilder.setProvider(new BouncyCastleProvider());

        return this.toPem(
            password,
            encryptorBuilder,
            new StringWriterFactory(),
            new PemWriterFactory()
        );
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
        return this.toPem(null, null, stringWriterFactory, pemWriterFactory);
    }

    /**
     * Get this key as an encrypted PEM formatted string.
     *
     * @param password            A password to encrypt the PEM data with.
     * @param encryptorBuilder    The encryptor builder to use.
     * @param stringWriterFactory The string writer factory to use.
     * @param pemWriterFactory    The PEM writer factory to use.
     *
     * @return The PEM formatted key.
     */
    public String toPem(
        final String password,
        final JcePEMEncryptorBuilder encryptorBuilder,
        final StringWriterFactoryInterface stringWriterFactory,
        final PemWriterFactoryInterface pemWriterFactory
    ) {
        PEMEncryptor encryptor = null;
        if (null != password) {
            encryptor = encryptorBuilder.build(password.toCharArray());
        }

        StringWriter stringWriter = stringWriterFactory.create();
        PEMWriter pemWriter = pemWriterFactory.create(stringWriter);

        IOException error = null;
        try {
            if (null == encryptor) {
                pemWriter.writeObject(this.bcPrivateKeyInfo());
            } else {
                pemWriter.writeObject(this.bcPrivateKeyInfo(), encryptor);
            }
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
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger primeExponent1;
    private BigInteger primeExponent2;
    private BigInteger coefficient;
}
