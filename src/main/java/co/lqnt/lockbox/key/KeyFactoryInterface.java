/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.PrivateKeyReadException;
import co.lqnt.lockbox.key.exception.PublicKeyReadException;
import java.io.File;
import java.io.InputStream;

/**
 * The interface implemented by key factories.
 */
interface KeyFactoryInterface
{
    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final InputStream input)
        throws PrivateKeyReadException;

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final byte[] input)
        throws PrivateKeyReadException;

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final String input)
        throws PrivateKeyReadException;

    /**
     * Create a private key from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The private key.
     * @throws PrivateKeyReadException If reading of the private key fails.
     */
    public PrivateKey createPrivateKey(final File input)
        throws PrivateKeyReadException;

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
        throws PrivateKeyReadException;

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
        throws PrivateKeyReadException;

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
        throws PrivateKeyReadException;

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
        final File input,
        final String password
    )
        throws PrivateKeyReadException;

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
