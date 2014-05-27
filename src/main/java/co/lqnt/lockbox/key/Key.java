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
import co.lqnt.lockbox.key.exception.InvalidKeyParameterException;
import com.google.common.base.Optional;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents an encryption key.
 */
public class Key implements KeyInterface
{
    /**
     * Construct a new key.
     *
     * @param encryptSecret The encrypt secret.
     * @param authSecret    The auth secret.
     *
     * @throws InvalidKeyParameterException If any of the supplied parameters are invalid.
     */
    public Key(
        final List<Byte> encryptSecret,
        final List<Byte> authSecret
    ) throws
        InvalidKeyParameterException
    {
        this(encryptSecret, authSecret, null, null);
    }

    /**
     * Construct a new key.
     *
     * @param encryptSecret The encrypt secret.
     * @param authSecret    The auth secret.
     * @param name          The name.
     *
     * @throws InvalidKeyParameterException If any of the supplied parameters are invalid.
     */
    public Key(
        final List<Byte> encryptSecret,
        final List<Byte> authSecret,
        final String name
    ) throws
        InvalidKeyParameterException
    {
        this(encryptSecret, authSecret, name, null);
    }

    /**
     * Construct a new key.
     *
     * @param encryptSecret The encrypt secret.
     * @param authSecret    The auth secret.
     * @param name          The name.
     * @param description   The description.
     *
     * @throws InvalidKeyParameterException If any of the supplied parameters are invalid.
     */
    public Key(
        final List<Byte> encryptSecret,
        final List<Byte> authSecret,
        final String name,
        final String description
    ) throws
        InvalidKeyParameterException
    {
        switch (encryptSecret.size()) {
            case 32:
            case 24:
            case 16:
                break;

            default:
                throw new InvalidEncryptSecretSizeException(
                    encryptSecret.size() * 8
                );
        }

        switch (authSecret.size()) {
            case 64:
            case 48:
            case 32:
            case 28:
                break;

            default:
                throw new InvalidAuthSecretSizeException(
                    authSecret.size() * 8
                );
        }

        this.encryptSecret = new ArrayList<Byte>(encryptSecret);
        this.encryptSecretBytes = encryptSecret.size();
        this.encryptSecretBits = encryptSecret.size() * 8;
        this.authSecret = new ArrayList<Byte>(authSecret);
        this.authSecretBytes = authSecret.size();
        this.authSecretBits = authSecret.size() * 8;
        this.name = Optional.fromNullable(name);
        this.description = Optional.fromNullable(description);
    }

    /**
     * Get the encrypt secret.
     *
     * @return The encrypt secret.
     */
    public List<Byte> encryptSecret()
    {
        return new ArrayList<Byte>(this.encryptSecret);
    }

    /**
     * Get the size of the encrypt secret in bytes.
     *
     * @return The size of the encrypt secret in bytes.
     */
    public int encryptSecretBytes()
    {
        return this.encryptSecretBytes;
    }

    /**
     * Get the size of the encrypt secret in bits.
     *
     * @return The size of the encrypt secret in bits.
     */
    public int encryptSecretBits()
    {
        return this.encryptSecretBits;
    }

    /**
     * Get the auth secret.
     *
     * @return The auth secret.
     */
    public List<Byte> authSecret()
    {
        return new ArrayList<Byte>(this.authSecret);
    }

    /**
     * Get the size of the auth secret in bytes.
     *
     * @return The size of the auth secret in bytes.
     */
    public int authSecretBytes()
    {
        return this.authSecretBytes;
    }

    /**
     * Get the size of the auth secret in bits.
     *
     * @return The size of the auth secret in bits.
     */
    public int authSecretBits()
    {
        return this.authSecretBits;
    }

    /**
     * Get the name.
     *
     * @return The name.
     */
    public Optional<String> name()
    {
        return this.name;
    }

    /**
     * Get the description.
     *
     * @return The description.
     */
    public Optional<String> description()
    {
        return this.description;
    }

    /**
     * Erase these parameters, removing any sensitive data.
     */
    public void erase()
    {
        Collections.fill(this.encryptSecret, (byte) 0);
        Collections.fill(this.authSecret, (byte) 0);
        this.name = Optional.<String>absent();
        this.description = Optional.<String>absent();
    }

    final private List<Byte> encryptSecret;
    final private int encryptSecretBytes;
    final private int encryptSecretBits;
    final private List<Byte> authSecret;
    final private int authSecretBytes;
    final private int authSecretBits;
    private Optional<String> name;
    private Optional<String> description;
}
