/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidAuthSecretSizeException;
import co.lqnt.lockbox.key.exception.InvalidEncryptSecretSizeException;
import co.lqnt.lockbox.random.RandomSourceInterface;
import co.lqnt.lockbox.random.SecureRandom;

/**
 * The interface implemented by encryption key generators.
 */
public class KeyGenerator implements KeyGeneratorInterface
{
    /**
     * Get the static instance of this generator.
     *
     * @return The static generator.
     */
    static public KeyGenerator instance()
    {
        if (null == KeyGenerator.instance) {
            KeyGenerator.instance = new KeyGenerator();
        }

        return KeyGenerator.instance;
    }

    /**
     * Construct a new key generator.
     */
    public KeyGenerator()
    {
        this.factory = KeyFactory.instance();
        this.randomSource = SecureRandom.instance();
    }

    /**
     * Construct a new key generator.
     *
     * @param factory      The key factory to use.
     * @param randomSource The random source to use.
     */
    public KeyGenerator(
        final KeyFactoryInterface factory,
        final RandomSourceInterface randomSource
    ) {
        this.factory = factory;
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
     * Get the random source.
     *
     * @return The random source.
     */
    public RandomSourceInterface randomSource()
    {
        return this.randomSource;
    }

    /**
     * Generate a new key.
     *
     * @return The generated key.
     */
    public KeyInterface generateKey()
    {
        return this.generateKey(null, null);
    }

    /**
     * Generate a new key.
     *
     * @param name The name.
     *
     * @return The generated key.
     */
    public KeyInterface generateKey(final String name)
    {
        return this.generateKey(name, null);
    }

    /**
     * Generate a new key.
     *
     * @param name The name.
     * @param description The description.
     *
     * @return The generated key.
     */
    public KeyInterface generateKey(
        final String name,
        final String description
    ) {
        KeyInterface key;
        try {
            key = this.generateKey(name, description, 256, 256);
        } catch (InvalidEncryptSecretSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidAuthSecretSizeException e) {
            throw new RuntimeException(e);
        }

        return key;
    }

    /**
     * Generate a new key.
     *
     * @param encryptSecretBits The size of the encrypt secret in bits.
     * @param authSecretBits    The size of the auth secret in bits.
     *
     * @return The generated key.
     * @throws InvalidEncryptSecretSizeException If the requested encrypt secret size is invalid.
     * @throws InvalidAuthSecretSizeException    If the requested auth secret size is invalid.
     */
    public KeyInterface generateKey(
        final int encryptSecretBits,
        final int authSecretBits
    ) throws
        InvalidEncryptSecretSizeException,
        InvalidAuthSecretSizeException
    {
        return this.generateKey(
            null,
            null,
            encryptSecretBits,
            authSecretBits
        );
    }

    /**
     * Generate a new key.
     *
     * @param name              The name.
     * @param description       The description.
     * @param encryptSecretBits The size of the encrypt secret in bits.
     * @param authSecretBits    The size of the auth secret in bits.
     *
     * @return The generated key.
     * @throws InvalidEncryptSecretSizeException If the requested encrypt secret size is invalid.
     * @throws InvalidAuthSecretSizeException    If the requested auth secret size is invalid.
     */
    public KeyInterface generateKey(
        final String name,
        final String description,
        final int encryptSecretBits,
        final int authSecretBits
    ) throws
        InvalidEncryptSecretSizeException,
        InvalidAuthSecretSizeException
    {
        switch (encryptSecretBits) {
            case 256:
            case 192:
            case 128:
                break;

            default:
                throw new InvalidEncryptSecretSizeException(encryptSecretBits);
        }

        switch (authSecretBits) {
            case 512:
            case 384:
            case 256:
            case 224:
                break;

            default:
                throw new InvalidAuthSecretSizeException(authSecretBits);
        }

        return this.factory().createKey(
            this.randomSource().generate(encryptSecretBits / 8),
            this.randomSource().generate(authSecretBits / 8),
            name,
            description
        );
    }

    static private KeyGenerator instance;
    final private KeyFactoryInterface factory;
    final private RandomSourceInterface randomSource;
}
