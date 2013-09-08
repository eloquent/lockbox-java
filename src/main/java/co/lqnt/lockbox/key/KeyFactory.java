/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.util.PemParserFactory;
import co.lqnt.lockbox.key.exception.PrivateKeyReadException;
import co.lqnt.lockbox.key.exception.PublicKeyReadException;
import co.lqnt.lockbox.util.BcKeyParametersFactory;
import co.lqnt.lockbox.util.BcKeyParametersFactoryInterface;
import co.lqnt.lockbox.util.PemParserFactoryInterface;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

/**
 * Creates encryption keys.
 */
public class KeyFactory implements KeyFactoryInterface
{
    /**
     * Construct a new key factory.
     */
    public KeyFactory()
    {
        this.pemParserFactory = new PemParserFactory();
        this.bcKeyParametersFactory = new BcKeyParametersFactory();

        this.decryptorProviderBuilder =
            new JcePEMDecryptorProviderBuilder();
        this.decryptorProviderBuilder.setProvider(new BouncyCastleProvider());
    }

    /**
     * Construct a new key factory.
     *
     * @param pemParserFactory             The PEM parser factory to use.
     * @param bcPublicKeyParametersFactory The Bouncy Castle public key parameters factory to use.
     * @param decryptorProviderBuilder     The decryptor provider builder to use.
     */
    public KeyFactory(
        final PemParserFactoryInterface pemParserFactory,
        final BcKeyParametersFactoryInterface bcPublicKeyParametersFactory,
        final JcePEMDecryptorProviderBuilder decryptorProviderBuilder
    ) {
        this.pemParserFactory = pemParserFactory;
        this.bcKeyParametersFactory = bcPublicKeyParametersFactory;
        this.decryptorProviderBuilder = decryptorProviderBuilder;
    }

    /**
     * Get the PEM parser factory.
     *
     * @return The PEM parser factory.
     */
    public PemParserFactoryInterface pemParserFactory()
    {
        return this.pemParserFactory;
    }

    /**
     * Get the Bouncy Castle public key parameters factory.
     *
     * @return The Bouncy Castle public key parameters factory.
     */
    public BcKeyParametersFactoryInterface bcKeyParametersFactory()
    {
        return this.bcKeyParametersFactory;
    }

    /**
     * Get the decryptor provider builder.
     *
     * @return The decryptor provider builder.
     */
    public JcePEMDecryptorProviderBuilder decryptorProviderBuilder()
    {
        return this.decryptorProviderBuilder;
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final InputStream input)
        throws PrivateKeyReadException
    {
        Object pemObject;
        try {
            pemObject = this.parsePemObject(input);
        } catch (PEMException e) {
            throw new PrivateKeyReadException(e);
        }

        PEMKeyPair pemKeyPair;
        if (pemObject instanceof PEMKeyPair) {
            pemKeyPair = (PEMKeyPair) pemObject;
        } else {
            throw new PrivateKeyReadException();
        }

        return this.convertPrivateKey(pemKeyPair);
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final byte[] input)
        throws PrivateKeyReadException
    {
        return this.createPrivateKey(new ByteArrayInputStream(input));
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final String input)
        throws PrivateKeyReadException
    {
        return this.createPrivateKey(
            input.getBytes(Charset.forName("US-ASCII"))
        );
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final File input)
        throws PrivateKeyReadException
    {
        InputStream inputStream = null;
        PrivateKey privateKey;
        try {
            inputStream = new FileInputStream(input);
            privateKey = this.createPrivateKey(inputStream);
        } catch (FileNotFoundException e) {
            throw new PrivateKeyReadException(e);
        } finally {
            this.closeInputStream(inputStream);
        }

        return privateKey;
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(
        final InputStream input,
        final String password
    )
        throws PrivateKeyReadException
    {
        Object pemObject;
        try {
            pemObject = this.parsePemObject(input);
        } catch (PEMException e) {
            throw new PrivateKeyReadException(e);
        }

        PEMEncryptedKeyPair encryptedKeyPair;
        if (pemObject instanceof PEMEncryptedKeyPair) {
            encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;
        } else {
            throw new PrivateKeyReadException();
        }

        PEMDecryptorProvider decryptorProvider = this.decryptorProviderBuilder()
            .build(password.toCharArray());

        PEMKeyPair pemKeyPair;
        try {
            pemKeyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
        } catch (IOException e) {
            throw new PrivateKeyReadException(e);
        }

        return this.convertPrivateKey(pemKeyPair);
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(
        final byte[] input,
        final String password
    )
        throws PrivateKeyReadException
    {
        return this.createPrivateKey(new ByteArrayInputStream(input), password);
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(
        final String input,
        final String password
    )
        throws PrivateKeyReadException
    {
        return this.createPrivateKey(
            input.getBytes(Charset.forName("US-ASCII")),
            password
        );
    }

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final File input, final String password)
        throws PrivateKeyReadException
    {
        InputStream inputStream = null;
        PrivateKey privateKey;
        try {
            inputStream = new FileInputStream(input);
            privateKey = this.createPrivateKey(inputStream, password);
        } catch (FileNotFoundException e) {
            throw new PrivateKeyReadException(e);
        } finally {
            this.closeInputStream(inputStream);
        }

        return privateKey;
    }

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final InputStream input)
        throws PublicKeyReadException
    {
        Object pemObject;
        try {
            pemObject = this.parsePemObject(input);
        } catch (PEMException e) {
            throw new PublicKeyReadException(e);
        }

        SubjectPublicKeyInfo publicKeyInfo;
        if (pemObject instanceof SubjectPublicKeyInfo) {
            publicKeyInfo = (SubjectPublicKeyInfo) pemObject;
        } else {
            throw new PublicKeyReadException();
        }

        AsymmetricKeyParameter keyParameter;
        try {
            keyParameter = this.bcKeyParametersFactory()
                .createPublicKeyParameters(publicKeyInfo);
        } catch (IOException e) {
            throw new PublicKeyReadException(e);
        }

        RSAKeyParameters publicKeyParameters;
        if (keyParameter instanceof RSAKeyParameters) {
            publicKeyParameters = (RSAKeyParameters) keyParameter;
        } else {
            throw new PublicKeyReadException();
        }

        return new PublicKey(
            publicKeyParameters.getModulus(),
            publicKeyParameters.getExponent()
        );
    }

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final byte[] input)
        throws PublicKeyReadException
    {
        return this.createPublicKey(new ByteArrayInputStream(input));
    }

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final String input)
        throws PublicKeyReadException
    {
        return this.createPublicKey(
            input.getBytes(Charset.forName("US-ASCII"))
        );
    }

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final File input)
        throws PublicKeyReadException
    {
        InputStream inputStream = null;
        PublicKey publicKey;
        try {
            inputStream = new FileInputStream(input);
            publicKey = this.createPublicKey(inputStream);
        } catch (FileNotFoundException e) {
            throw new PublicKeyReadException(e);
        } finally {
            this.closeInputStream(inputStream);
        }

        return publicKey;
    }

    /**
     * Parses PEM data and returns a specialized object.
     *
     * @param input The PEM data to read.
     *
     * @return The specialized object.
     * @throws PEMException If the PEM data is invalid.
     */
    protected Object parsePemObject(final InputStream input) throws PEMException
    {
        PEMParser parser = this.pemParserFactory.create(input);
        Object pemObject;
        try {
            pemObject = parser.readObject();
        } catch (IOException e) {
            throw new PEMException("Unable to read PEM stream.", e);
        }

        if (null == pemObject) {
            throw new PEMException("No PEM data found.");
        }

        return pemObject;
    }

    /**
     * Convert a PEM key pair to a Lockbox private key.
     *
     * @param pemKeyPair The PEM key pair.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    protected PrivateKey convertPrivateKey(final PEMKeyPair pemKeyPair)
        throws PrivateKeyReadException
    {
        AsymmetricKeyParameter keyParameter;
        try {
            keyParameter = this.bcKeyParametersFactory()
                .createPrivateKeyParameters(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            throw new PrivateKeyReadException(e);
        }

        RSAPrivateCrtKeyParameters privateKeyParameters;
        if (keyParameter instanceof RSAPrivateCrtKeyParameters) {
            privateKeyParameters = (RSAPrivateCrtKeyParameters) keyParameter;
        } else {
            throw new PrivateKeyReadException();
        }

        return new PrivateKey(
            privateKeyParameters.getModulus(),
            privateKeyParameters.getPublicExponent(),
            privateKeyParameters.getExponent(),
            privateKeyParameters.getP(),
            privateKeyParameters.getQ(),
            privateKeyParameters.getDP(),
            privateKeyParameters.getDQ(),
            privateKeyParameters.getQInv()
        );
    }

    /**
     * Close an input stream or die trying.
     *
     * @param input The input stream to close.
     *
     * @throws RuntimeException If the stream cannot be closed.
     */
    protected void closeInputStream(final InputStream input)
    {
        if (null == input) {
            return;
        }

        try {
            input.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to close stream.", e);
        }
    }

    private PemParserFactoryInterface pemParserFactory;
    private BcKeyParametersFactoryInterface bcKeyParametersFactory;
    private JcePEMDecryptorProviderBuilder decryptorProviderBuilder;
}
