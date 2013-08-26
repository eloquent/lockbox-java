/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.key;

import co.lqnt.lockbox.key.exception.InvalidPrivateKeyException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

/**
 * Creates encryption keys.
 */
class KeyFactory implements KeyFactoryInterface
{
    /**
     * Construct a new key factory.
     */
    public KeyFactory()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param key The PEM formatted private key.
     *
     * @return The key pair.
     * @throws InvalidPrivateKeyException If the key is invalid.
     */
    public KeyPair createKeyPair(final byte[] key)
        throws InvalidPrivateKeyException
    {
        Reader keyReader = new BufferedReader(
            new InputStreamReader(
                new ByteArrayInputStream(key),
                Charset.forName("US-ASCII")
            )
        );
        PEMReader pemReader = new PEMReader(keyReader);

        KeyPair keyPair;
        try {
            keyPair = (KeyPair) pemReader.readObject();
        } catch (IOException e) {
            throw new InvalidPrivateKeyException(key, e);
        }

        return keyPair;
    }
}
