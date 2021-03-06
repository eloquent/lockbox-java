/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.codec.Base64UriCodec;
import co.lqnt.lockbox.util.codec.CodecInterface;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.testng.Assert;
import org.testng.annotations.Test;

public class EncryptionCipherTest
{
    public EncryptionCipherTest() throws Throwable
    {
        this.base64UriCodec = new Base64UriCodec();
        this.rsaCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        this.aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.sha1Digest = new SHA1Digest();
        this.random = new SecureRandom();
        this.encryptionCipher = new EncryptionCipher(
            this.base64UriCodec,
            this.rsaCipher,
            this.aesCipher,
            this.sha1Digest,
            this.random
        );
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.encryptionCipher.base64UriCodec(), this.base64UriCodec);
        Assert.assertSame(this.encryptionCipher.rsaCipher(), this.rsaCipher);
        Assert.assertSame(this.encryptionCipher.aesCipher(), this.aesCipher);
        Assert.assertSame(this.encryptionCipher.sha1Digest(), this.sha1Digest);
        Assert.assertSame(this.encryptionCipher.random(), this.random);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.encryptionCipher = new EncryptionCipher();

        Assert.assertSame(this.encryptionCipher.base64UriCodec().getClass(), Base64UriCodec.class);
        Assert.assertSame(this.encryptionCipher.rsaCipher().getClass(), OAEPEncoding.class);
        Assert.assertSame(this.encryptionCipher.aesCipher().getClass(), PaddedBufferedBlockCipher.class);
        Assert.assertSame(this.encryptionCipher.sha1Digest().getClass(), SHA1Digest.class);
        Assert.assertSame(this.encryptionCipher.random().getClass(), SecureRandom.class);
    }

    private CodecInterface base64UriCodec;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private Digest sha1Digest;
    private SecureRandom random;
    private EncryptionCipher encryptionCipher;
}
