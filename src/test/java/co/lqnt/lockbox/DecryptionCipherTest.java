/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

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

public class DecryptionCipherTest
{
    public DecryptionCipherTest() throws Throwable
    {
        this.base64UriCodec = new Base64UriCodec();
        this.rsaCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        this.aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        this.sha1Digest = new SHA1Digest();
        this.decryptionCipher = new DecryptionCipher(
            this.base64UriCodec,
            this.rsaCipher,
            this.aesCipher,
            this.sha1Digest
        );
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.decryptionCipher.base64UriCodec(), this.base64UriCodec);
        Assert.assertSame(this.decryptionCipher.rsaCipher(), this.rsaCipher);
        Assert.assertSame(this.decryptionCipher.aesCipher(), this.aesCipher);
        Assert.assertSame(this.decryptionCipher.sha1Digest(), this.sha1Digest);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.decryptionCipher = new DecryptionCipher();

        Assert.assertSame(this.decryptionCipher.base64UriCodec().getClass(), Base64UriCodec.class);
        Assert.assertSame(this.decryptionCipher.rsaCipher().getClass(), OAEPEncoding.class);
        Assert.assertSame(this.decryptionCipher.aesCipher().getClass(), PaddedBufferedBlockCipher.class);
        Assert.assertSame(this.decryptionCipher.sha1Digest().getClass(), SHA1Digest.class);
    }

    private CodecInterface base64UriCodec;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private Digest sha1Digest;
    private DecryptionCipher decryptionCipher;
}
