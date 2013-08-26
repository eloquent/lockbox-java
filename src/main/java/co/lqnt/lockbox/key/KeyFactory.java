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
        Reader reader = new BufferedReader(
            new InputStreamReader(
                new ByteArrayInputStream(key),
                Charset.forName("US-ASCII")
            )
        );

        KeyPair keyPair;
        try {
            keyPair = (KeyPair) this.readPem(reader);
        } catch (IOException e) {
            throw new RuntimeException("Unknown PEMReader failure.");
        }

        if (null == keyPair) {
            throw new InvalidPrivateKeyException(key);
        }

        return keyPair;
    }

    /**
     * Wraps PEMReader so that IOExceptions can be mocked.
     *
     * @param reader The reader to read from.
     *
     * @return The resulting object.
     * @throws IOException If PEMReader throws an IOException.
     */
    public Object readPem(Reader reader) throws IOException
    {
        Security.addProvider(new BouncyCastleProvider());
        PEMReader pemReader = new PEMReader(reader);

        return pemReader.readObject();
    }
}
