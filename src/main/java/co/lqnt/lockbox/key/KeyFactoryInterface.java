/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.KeyPairReadException;
import co.lqnt.lockbox.key.exception.PublicKeyReadException;
import java.io.File;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * The interface implemented by key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final InputStream input)
        throws KeyPairReadException;

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final byte[] input)
        throws KeyPairReadException;

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final String input)
        throws KeyPairReadException;

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final File input)
        throws KeyPairReadException;

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
        throws KeyPairReadException;

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
        throws KeyPairReadException;

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
        throws KeyPairReadException;

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input    The PEM data to read.
     * @param password The password to use to decrypt the key.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(final File input, final String password)
        throws KeyPairReadException;

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final InputStream input)
        throws PublicKeyReadException;

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final byte[] input)
        throws PublicKeyReadException;

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final String input)
        throws PublicKeyReadException;

    /**
     * Create a public key from a PEM formatted public key.
     *
     * @param input The PEM data to read.
     *
     * @return The public key
     * @throws PublicKeyReadException If reading of the public key fails.
     */
    public PublicKey createPublicKey(final File input)
        throws PublicKeyReadException;
}
