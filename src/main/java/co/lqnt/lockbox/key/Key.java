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
import com.google.common.base.Optional;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an encryption key.
 */
public class Key implements KeyInterface
{
    /**
     * Construct a new key.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     *
     * @throws InvalidEncryptionSecretSizeException     If the encryption secret is an invalid size.
     * @throws InvalidAuthenticationSecretSizeException If the authentication secret is an invalid size.
     */
    public Key(
        final List<Byte> encryptionSecret,
        final List<Byte> authenticationSecret
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException
    {
        this(encryptionSecret, authenticationSecret, null, null);
    }

    /**
     * Construct a new key.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     *
     * @throws InvalidEncryptionSecretSizeException     If the encryption secret is an invalid size.
     * @throws InvalidAuthenticationSecretSizeException If the authentication secret is an invalid size.
     */
    public Key(
        final List<Byte> encryptionSecret,
        final List<Byte> authenticationSecret,
        final String name
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException
    {
        this(encryptionSecret, authenticationSecret, name, null);
    }

    /**
     * Construct a new key.
     *
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     * @param description          The description.
     *
     * @throws InvalidEncryptionSecretSizeException     If the encryption secret is an invalid size.
     * @throws InvalidAuthenticationSecretSizeException If the authentication secret is an invalid size.
     */
    public Key(
        final List<Byte> encryptionSecret,
        final List<Byte> authenticationSecret,
        final String name,
        final String description
    ) throws
        InvalidEncryptionSecretSizeException,
        InvalidAuthenticationSecretSizeException
    {
        switch (encryptionSecret.size()) {
            case 32:
            case 24:
            case 16:
                break;

            default:
                throw new InvalidEncryptionSecretSizeException(
                    encryptionSecret.size() * 8
                );
        }

        switch (authenticationSecret.size()) {
            case 64:
            case 48:
            case 32:
            case 28:
                break;

            default:
                throw new InvalidAuthenticationSecretSizeException(
                    authenticationSecret.size() * 8
                );
        }

        this.encryptionSecret = new ArrayList<Byte>(encryptionSecret);
        this.encryptionSecretBytes = encryptionSecret.size();
        this.encryptionSecretBits = encryptionSecret.size() * 8;
        this.authenticationSecret = new ArrayList<Byte>(authenticationSecret);
        this.authenticationSecretBytes = authenticationSecret.size();
        this.authenticationSecretBits = authenticationSecret.size() * 8;
        this.name = Optional.fromNullable(name);
        this.description = Optional.fromNullable(description);
    }

    /**
     * Get the encryption secret.
     *
     * @return The encryption secret.
     */
    public List<Byte> encryptionSecret()
    {
        return new ArrayList<Byte>(this.encryptionSecret);
    }

    /**
     * Get the size of the encryption secret in bytes.
     *
     * @return The size of the encryption secret in bytes.
     */
    public int encryptionSecretBytes()
    {
        return this.encryptionSecretBytes;
    }

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return The size of the encryption secret in bits.
     */
    public int encryptionSecretBits()
    {
        return this.encryptionSecretBits;
    }

    /**
     * Get the authentication secret.
     *
     * @return The authentication secret.
     */
    public List<Byte> authenticationSecret()
    {
        return new ArrayList<Byte>(this.authenticationSecret);
    }

    /**
     * Get the size of the authentication secret in bytes.
     *
     * @return The size of the authentication secret in bytes.
     */
    public int authenticationSecretBytes()
    {
        return this.authenticationSecretBytes;
    }

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return The size of the authentication secret in bits.
     */
    public int authenticationSecretBits()
    {
        return this.authenticationSecretBits;
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

    final private List<Byte> encryptionSecret;
    final private int encryptionSecretBytes;
    final private int encryptionSecretBits;
    final private List<Byte> authenticationSecret;
    final private int authenticationSecretBytes;
    final private int authenticationSecretBits;
    final private Optional<String> name;
    final private Optional<String> description;
}
