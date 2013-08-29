/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.pem.PemParserFactory;
import co.lqnt.lockbox.key.exception.KeyPairReadException;
import co.lqnt.lockbox.key.exception.PublicKeyReadException;
import co.lqnt.lockbox.pem.PemParserFactoryInterface;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

/**
 * Creates encryption keys.
 */
public class KeyFactory implements KeyFactoryInterface
{
    /**
     * Construct a new key factory.
     *
     * @throws RuntimeException If the RSA key factory is unavailable.
     */
    public KeyFactory()
    {
        Provider provider = new BouncyCastleProvider();

        this.pemParserFactory = new PemParserFactory();

        this.decryptorProviderBuilder =
            new JcePEMDecryptorProviderBuilder();
        this.decryptorProviderBuilder.setProvider(provider);

        this.keyConverter = new JcaPEMKeyConverter();
        this.keyConverter.setProvider(provider);
    }

    /**
     * Construct a new key factory.
     *
     * @param pemParserFactory         The PEM parser factory to use.
     * @param decryptorProviderBuilder The decryptor provider builder to use.
     * @param keyConverter             The key converter to use.
     */
    public KeyFactory(
        final PemParserFactoryInterface pemParserFactory,
        final JcePEMDecryptorProviderBuilder decryptorProviderBuilder,
        final JcaPEMKeyConverter keyConverter
    ) {
        this.pemParserFactory = pemParserFactory;
        this.decryptorProviderBuilder = decryptorProviderBuilder;
        this.keyConverter = keyConverter;
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
     * Get the decryptor provider builder.
     *
     * @return The decryptor provider builder.
     */
    public JcePEMDecryptorProviderBuilder decryptorProviderBuilder()
    {
        return this.decryptorProviderBuilder;
    }

    /**
     * Get the key converter.
     *
     * @return The key converter.
     */
    public JcaPEMKeyConverter keyConverter()
    {
        return this.keyConverter;
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final InputStream input)
        throws KeyPairReadException
    {
        Object pemObject;
        try {
            pemObject = this.parsePemObject(input);
        } catch (PEMException e) {
            throw new KeyPairReadException(e);
        }

        PEMKeyPair pemKeyPair;
        if (pemObject instanceof PEMKeyPair) {
            pemKeyPair = (PEMKeyPair) pemObject;
        } else {
            throw new KeyPairReadException();
        }

        return this.convertKeyPair(pemKeyPair);
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final byte[] input)
        throws KeyPairReadException
    {
        return this.createKeyPair(new ByteArrayInputStream(input));
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final String input)
        throws KeyPairReadException
    {
        return this.createKeyPair(input.getBytes(Charset.forName("US-ASCII")));
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final InputStream input, final String password)
        throws KeyPairReadException
    {
        Object pemObject;
        try {
            pemObject = this.parsePemObject(input);
        } catch (PEMException e) {
            throw new KeyPairReadException(e);
        }

        PEMEncryptedKeyPair encryptedKeyPair;
        if (pemObject instanceof PEMEncryptedKeyPair) {
            encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;
        } else {
            throw new KeyPairReadException();
        }

        PEMDecryptorProvider decryptorProvider = this.decryptorProviderBuilder()
            .build(password.toCharArray());

        PEMKeyPair pemKeyPair;
        try {
            pemKeyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
        } catch (IOException e) {
            throw new KeyPairReadException(e);
        }

        return this.convertKeyPair(pemKeyPair);
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final byte[] input, final String password)
        throws KeyPairReadException
    {
        return this.createKeyPair(new ByteArrayInputStream(input), password);
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final String input, final String password)
        throws KeyPairReadException
    {
        return this.createKeyPair(
            input.getBytes(Charset.forName("US-ASCII")),
            password
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

        PublicKey publicKey;
        try {
            publicKey = this.keyConverter().getPublicKey(publicKeyInfo);
        } catch (PEMException e) {
            throw new PublicKeyReadException(e);
        }

        return publicKey;
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
     * Converts a PEM key pair into a standard JCE key pair.
     *
     * @param pemKeyPair The PEM key pair.
     *
     * @return The JCE key pair.
     * @throws KeyPairReadException If the conversion cannot be performed.
     */
    protected KeyPair convertKeyPair(final PEMKeyPair pemKeyPair)
        throws KeyPairReadException
    {
        KeyPair keyPair;
        try {
            keyPair = this.keyConverter().getKeyPair(pemKeyPair);
        } catch (PEMException e) {
            throw new KeyPairReadException(e);
        }

        return keyPair;
    }

    private PemParserFactoryInterface pemParserFactory;
    private JcePEMDecryptorProviderBuilder decryptorProviderBuilder;
    private JcaPEMKeyConverter keyConverter;
}
