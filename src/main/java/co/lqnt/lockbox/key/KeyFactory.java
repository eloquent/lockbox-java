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
import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.SecureRandomInterface;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

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
        BouncyCastleProvider provider = new BouncyCastleProvider();

        this.pemParserFactory = new PemParserFactory();
        this.bcKeyParametersFactory = new BcKeyParametersFactory();

        this.pemDecryptorProviderBuilder =
            new JcePEMDecryptorProviderBuilder();
        this.pemDecryptorProviderBuilder.setProvider(provider);
        this.pkcs8DecryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        this.pkcs8DecryptorProviderBuilder.setProvider(provider);

        this.keyGenerator = new RSAKeyPairGenerator();
        this.random = new SecureRandom();
    }

    /**
     * Construct a new key factory.
     *
     * @param pemParserFactory              The PEM parser factory to use.
     * @param bcPublicKeyParametersFactory  The public key parameters factory to use.
     * @param pemDecryptorProviderBuilder   The PEM decryptor provider builder to use.
     * @param pkcs8DecryptorProviderBuilder The PKCS #8 decryptor provider builder to use.
     * @param keyGenerator                  The key generator to use.
     * @param random                        The secure random generator to use.
     */
    public KeyFactory(
        final PemParserFactoryInterface pemParserFactory,
        final BcKeyParametersFactoryInterface bcPublicKeyParametersFactory,
        final JcePEMDecryptorProviderBuilder pemDecryptorProviderBuilder,
        final JceOpenSSLPKCS8DecryptorProviderBuilder
            pkcs8DecryptorProviderBuilder,
        final AsymmetricCipherKeyPairGenerator keyGenerator,
        final SecureRandomInterface random
    ) {
        this.pemParserFactory = pemParserFactory;
        this.bcKeyParametersFactory = bcPublicKeyParametersFactory;
        this.pemDecryptorProviderBuilder = pemDecryptorProviderBuilder;
        this.pkcs8DecryptorProviderBuilder = pkcs8DecryptorProviderBuilder;
        this.keyGenerator = keyGenerator;
        this.random = random;
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
     * Get the PEM decryptor provider builder.
     *
     * @return The PEM decryptor provider builder.
     */
    public JcePEMDecryptorProviderBuilder pemDecryptorProviderBuilder()
    {
        return this.pemDecryptorProviderBuilder;
    }

    /**
     * Get the PKCS #8 decryptor provider builder.
     *
     * @return The PKCS #8 decryptor provider builder.
     */
    public JceOpenSSLPKCS8DecryptorProviderBuilder
        pkcs8DecryptorProviderBuilder()
    {
        return this.pkcs8DecryptorProviderBuilder;
    }

    /**
     * Get the Bouncy Castle key generator.
     *
     * @return The Bouncy Castle key generator.
     */
    public AsymmetricCipherKeyPairGenerator keyGenerator()
    {
        return this.keyGenerator;
    }

    /**
     * Get the secure random generator.
     *
     * @return The secure random generator.
     */
    public SecureRandomInterface random()
    {
        return this.random;
    }

    /**
     * Generate a new private key.
     *
     * @return The private key.
     */
    public PrivateKey generatePrivateKey()
    {
        return this.generatePrivateKey(2048);
    }

    /**
     * Generate a new private key.
     *
     * @param size The size of the key in bits.
     *
     * @return The private key.
     */
    public PrivateKey generatePrivateKey(final int size)
    {
        this.keyGenerator().init(
            new RSAKeyGenerationParameters(
                BigInteger.valueOf(65537),
                this.random().jceSecureRandom(),
                size,
                80
            )
        );

        AsymmetricKeyParameter keyParameters = this.keyGenerator()
            .generateKeyPair()
            .getPrivate();

        RSAPrivateCrtKeyParameters rsaKeyParameters;
        if (keyParameters instanceof RSAPrivateCrtKeyParameters) {
            rsaKeyParameters = (RSAPrivateCrtKeyParameters) keyParameters;
        } else {
            throw new RuntimeException(
                "Invalid key pair generated by Bouncy Castle."
            );
        }

        return new PrivateKey(
            rsaKeyParameters.getModulus(),
            rsaKeyParameters.getPublicExponent(),
            rsaKeyParameters.getExponent(),
            rsaKeyParameters.getP(),
            rsaKeyParameters.getQ(),
            rsaKeyParameters.getDP(),
            rsaKeyParameters.getDQ(),
            rsaKeyParameters.getQInv()
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
    public PrivateKey createPrivateKey(final InputStream input)
        throws PrivateKeyReadException
    {
        Object pemObject;
        try {
            pemObject = this.parsePemObject(input);
        } catch (PEMException e) {
            throw new PrivateKeyReadException(e);
        }

        if (pemObject instanceof PEMKeyPair) {
            return this.convertPrivateKey(
                ((PEMKeyPair) pemObject).getPrivateKeyInfo()
            );
        } else if (pemObject instanceof PrivateKeyInfo) {
            return this.convertPrivateKey((PrivateKeyInfo) pemObject);
        }

        throw new PrivateKeyReadException();
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

        if (pemObject instanceof PEMEncryptedKeyPair) {
            return this.decryptPemKeyPair(
                (PEMEncryptedKeyPair) pemObject,
                password
            );
        } else if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo) {
            return this.decryptPkcs8PrivateKey(
                (PKCS8EncryptedPrivateKeyInfo) pemObject,
                password
            );
        }

        throw new PrivateKeyReadException();
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
     * Decrypts an encrypted PEM key pair.
     *
     * @param encryptedKeyPair The key pair to decrypt.
     * @param password         The password to use.
     *
     * @return The decrypted private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    protected PrivateKey decryptPemKeyPair(
        PEMEncryptedKeyPair encryptedKeyPair,
        String password
    )
        throws PrivateKeyReadException
    {
        PEMDecryptorProvider decryptorProvider =
            this.pemDecryptorProviderBuilder().build(password.toCharArray());

        PEMKeyPair pemKeyPair;
        try {
            pemKeyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
        } catch (IOException e) {
            throw new PrivateKeyReadException(e);
        }

        return this.convertPrivateKey(pemKeyPair.getPrivateKeyInfo());
    }

    /**
     * Decrypts an encrypted PKCS #8 private key.
     *
     * @param encryptedPrivateKey The encrypted private key information.
     * @param password            The password to use.
     *
     * @return The decrypted private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    protected PrivateKey decryptPkcs8PrivateKey(
        PKCS8EncryptedPrivateKeyInfo encryptedPrivateKey,
        String password
    )
        throws PrivateKeyReadException
    {
        InputDecryptorProvider decryptorProvider;
        try {
            decryptorProvider = this.pkcs8DecryptorProviderBuilder()
                .build(password.toCharArray());
        } catch (OperatorCreationException e) {
            throw new PrivateKeyReadException(e);
        }

        PrivateKeyInfo privateKeyInfo;
        try {
            privateKeyInfo = encryptedPrivateKey.decryptPrivateKeyInfo(
                decryptorProvider
            );
        } catch (PKCSException e) {
            throw new PrivateKeyReadException(e);
        }

        return this.convertPrivateKey(privateKeyInfo);
    }

    /**
     * Convert Bouncy Castle private key info to a Lockbox private key.
     *
     * @param keyInformation The private key information.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    protected PrivateKey convertPrivateKey(final PrivateKeyInfo keyInformation)
        throws PrivateKeyReadException
    {
        AsymmetricKeyParameter keyParameter;
        try {
            keyParameter = this.bcKeyParametersFactory()
                .createPrivateKeyParameters(keyInformation);
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

    private AsymmetricCipherKeyPairGenerator keyGenerator;
    private PemParserFactoryInterface pemParserFactory;
    private BcKeyParametersFactoryInterface bcKeyParametersFactory;
    private JcePEMDecryptorProviderBuilder pemDecryptorProviderBuilder;
    private JceOpenSSLPKCS8DecryptorProviderBuilder
        pkcs8DecryptorProviderBuilder;
    private SecureRandomInterface random;
}
