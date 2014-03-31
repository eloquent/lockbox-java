/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2014 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import java.util.Arrays;

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
     */
    public Key(
        final byte[] encryptionSecret,
        final byte[] authenticationSecret
    ) {
        this.encryptionSecret =
            Arrays.copyOf(encryptionSecret, encryptionSecret.length);
        this.authenticationSecret =
            Arrays.copyOf(authenticationSecret, authenticationSecret.length);
        this.name = null;
        this.description = null;
    }
    
    /**
     * Construct a new key.
     * 
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     */
    public Key(
        final byte[] encryptionSecret,
        final byte[] authenticationSecret,
        final String name
    ) {
        this.encryptionSecret =
            Arrays.copyOf(encryptionSecret, encryptionSecret.length);
        this.authenticationSecret =
            Arrays.copyOf(authenticationSecret, authenticationSecret.length);
        this.name = name;
        this.description = null;
    }
    
    /**
     * Construct a new key.
     * 
     * @param encryptionSecret     The encryption secret.
     * @param authenticationSecret The authentication secret.
     * @param name                 The name.
     * @param description          The description.
     */
    public Key(
        final byte[] encryptionSecret,
        final byte[] authenticationSecret,
        final String name,
        final String description
    ) {
        this.encryptionSecret =
            Arrays.copyOf(encryptionSecret, encryptionSecret.length);
        this.authenticationSecret =
            Arrays.copyOf(authenticationSecret, authenticationSecret.length);
        this.name = name;
        this.description = description;
    }
    
    /**
     * Get the encryption secret.
     *
     * @return The encryption secret.
     */
    public byte[] encryptionSecret()
    {
        return Arrays
            .copyOf(this.encryptionSecret, this.encryptionSecret.length);
    }

    /**
     * Get the size of the encryption secret in bytes.
     *
     * @return The size of the encryption secret in bytes.
     */
    public int encryptionSecretBytes()
    {
        return this.encryptionSecret.length;
    }

    /**
     * Get the size of the encryption secret in bits.
     *
     * @return The size of the encryption secret in bits.
     */
    public int encryptionSecretBits()
    {
        return this.encryptionSecret.length * 8;
    }

    /**
     * Get the authentication secret.
     *
     * @return The authentication secret.
     */
    public byte[] authenticationSecret()
    {
        return Arrays.copyOf(
            this.authenticationSecret,
            this.authenticationSecret.length
        );
    }

    /**
     * Get the size of the authentication secret in bytes.
     *
     * @return The size of the authentication secret in bytes.
     */
    public int authenticationSecretBytes()
    {
        return this.authenticationSecret.length;
    }

    /**
     * Get the size of the authentication secret in bits.
     *
     * @return The size of the authentication secret in bits.
     */
    public int authenticationSecretBits()
    {
        return this.authenticationSecret.length * 8;
    }

    /**
     * Get the name.
     *
     * @return The name, or null if the key has no name.
     */
    public String name()
    {
        return this.name;
    }

    /**
     * Get the description.
     *
     * @return The description, or null if the key has no description.
     */
    public String description()
    {
        return this.description;
    }
    
    final private byte[] encryptionSecret;
    final private byte[] authenticationSecret;
    final private String name;
    final private String description;
}
