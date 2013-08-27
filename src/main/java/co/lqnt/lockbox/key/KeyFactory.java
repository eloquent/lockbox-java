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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.KeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Creates encryption keys.
 */
class KeyFactory
{
    public KeyFactory()
    {
        this.keyConverter = new JcaPEMKeyConverter();
        this.keyConverter.setProvider(new BouncyCastleProvider());
    }

    public KeyFactory(JcaPEMKeyConverter keyConverter)
    {
        this.keyConverter = keyConverter;
    }

    public JcaPEMKeyConverter keyConverter()
    {
        return this.keyConverter;
    }

    /**
     * Create a key pair from a PEM formatted private key.
     *
     * @param input The PEM data to read.
     *
     * @return The key pair.
     * @throws KeyPairReadException If reading of the key pair fails.
     */
    public KeyPair createKeyPair(InputStream input)
        throws KeyPairReadException
    {
        PEMParser parser = this.createParser(input);
        Object pemObject;
        try {
            pemObject = parser.readObject();
        } catch (IOException e) {
            throw new KeyPairReadException(e);
        }

        if (null == pemObject) {
            throw new KeyPairReadException();
        }

        PEMKeyPair pemKeyPair;
        if (pemObject instanceof PEMKeyPair) {
            pemKeyPair = (PEMKeyPair) pemObject;
        } else {
            throw new KeyPairReadException();
        }

        KeyPair keyPair;
        try {
            keyPair = this.keyConverter().getKeyPair(pemKeyPair);
        } catch (PEMException e) {
            throw new KeyPairReadException(e);
        }

        return keyPair;
    }

    protected PEMParser createParser(InputStream input)
    {
        return new PEMParser(
            new BufferedReader(
                new InputStreamReader(input, Charset.forName("US-ASCII"))
            )
        );
    }

    private JcaPEMKeyConverter keyConverter;
}
