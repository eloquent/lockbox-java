/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidAuthenticationSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidEncryptionSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidIterationsException;
import co.lqnt.lockbox.key.exception.InvalidSaltSizeException;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Derives keys from various data sources.
 */
public class KeyDeriver implements KeyDeriverInterface
{
    /**
     * Get the static instance of this deriver.
     *
     * @return The static deriver.
     */
    static public KeyDeriver instance()
    {
        if (null == KeyDeriver.instance) {
            KeyDeriver.instance = new KeyDeriver();
        }

        return KeyDeriver.instance;
    }

    /**
     * Construct a new key deriver.
     */
    public KeyDeriver()
    {
        this.factory = KeyFactory.instance();
        this.pbeParametersGenerator =
            new PKCS5S2ParametersGenerator(new SHA512Digest());
        this.randomSource = SecureRandom.instance();
    }

    /**
     * Construct a new key deriver.
     *
     * @param factory                The key factory to use.
     * @param pbeParametersGenerator The password-based encryption parameters generator to use.
     * @param randomSource           The random source to use.
     */
    public KeyDeriver(
        KeyFactoryInterface factory,
        PBEParametersGenerator pbeParametersGenerator,
        RandomSourceInterface randomSource
    ) {
        this.factory = factory;
        this.pbeParametersGenerator = pbeParametersGenerator;
        this.randomSource = randomSource;
    }

    /**
     * Get the key factory.
     *
     * @return The factory.
     */
    public KeyFactoryInterface factory()
    {
        return this.factory;
    }

    /**
     * Get the password-based encryption parameters generator.
     *
     * @return The password-based encryption parameters generator.
     */
    public PBEParametersGenerator pbeParametersGenerator()
    {
        return this.pbeParametersGenerator;
    }

    /**
     * Get the random source.
     *
     * @return The random source.
     */
    public RandomSourceInterface randomSource()
    {
        return this.randomSource;
    }

    /**
     * Derive a key from a password.
     *
     * @param password    The password.
     * @param iterations  The number of hash iterations to use.
     * @param salt        The salt to use.
     * @param name        The name.
     * @param description The description.
     *
     * @return The derived key.
     * @throws InvalidIterationsException If the number of iterations is invalid.
     * @throws InvalidSaltSizeException   If the salt size is invalid.
     */
    public KeyInterface deriveKeyFromPassword(
        byte[] password,
        int iterations,
        byte[] salt,
        String name,
        String description
    ) throws
        InvalidIterationsException,
        InvalidSaltSizeException
    {
        if (iterations < 1) {
            throw new InvalidIterationsException(iterations);
        }
        if (64 != salt.length) {
            throw new InvalidSaltSizeException(salt.length);
        }

        this.pbeParametersGenerator().init(password, salt, iterations);
        KeyParameter keyParameter = (KeyParameter) this.pbeParametersGenerator()
            .generateDerivedMacParameters(512);

        KeyInterface key;
        try {
            key = this.factory().createKey(
                Arrays.copyOfRange(keyParameter.getKey(), 0, 32),
                Arrays.copyOfRange(keyParameter.getKey(), 32, 64),
                name,
                description
            );
        } catch (InvalidEncryptionSecretSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidAuthenticationSecretSizeException e) {
            throw new RuntimeException(e);
        }

        return key;
    }

    static private KeyDeriver instance;
    final private KeyFactoryInterface factory;
    final private PBEParametersGenerator pbeParametersGenerator;
    final private RandomSourceInterface randomSource;
}
