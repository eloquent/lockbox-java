/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.test;

import co.lqnt.lockbox.BoundDecryptionCipher;
import co.lqnt.lockbox.BoundEncryptionCipher;
import co.lqnt.lockbox.Cipher;
import co.lqnt.lockbox.DecryptionCipher;
import co.lqnt.lockbox.EncryptionCipher;
import co.lqnt.lockbox.exception.DecryptionFailedException;
import co.lqnt.lockbox.key.KeyFactory;
import co.lqnt.lockbox.key.PrivateKey;
import co.lqnt.lockbox.key.PublicKey;
import co.lqnt.lockbox.key.exception.PrivateKeyReadException;
import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.codec.Base64UriCodec;
import java.io.File;
import java.net.URI;
import java.nio.charset.Charset;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class FunctionalTest
{
    public FunctionalTest() throws Throwable
    {
        this.encryptionCipher = new EncryptionCipher();
        this.decryptionCipher = new DecryptionCipher();
        this.cipher = new Cipher(this.encryptionCipher, this.decryptionCipher);

        this.keyFactory = new KeyFactory();

        this.exampleKeyFileUri = this.getClass().getClassLoader().getResource("pem/rsa-2048.private.pem").toURI();
    }

    @DataProvider(name = "specVectorData")
    public Object[][] specVectorData()
    {
        return new Object[][]{
            {
                2048,
                "",
                "12345678901234567890123456789012",
                "1234567890123456",
                "QJyn73i2dlN_V9o2fVLLmh4U85AIEL5v" +
                "Cch2sP5aw3CogMBn5qRpokg6OFjRxsYB" +
                "xb_Oqe8n9GALxJsuuqyZgWXxSK0exA2P" +
                "QnAECIcujG9EyM4GlQodJiJdMtDJh0Dd" +
                "frp7s87w7YWgleaK_3JVqEpjRolj1AWr" +
                "DjXeFDl_tGIZ1R95PD2mbq6OUgm1Q56M" +
                "CRLZdZJOm3yixcGHQOV2wv73YIbOvOa8" +
                "hEZ7ydX-VRHPMmJyFgUe9gv8G8sDm6xY" +
                "UEz1rIu62XwMoMB4B3UZo_r0Q9xCr4sx" +
                "BVPY7bOAp6AUjOuvsHwBGJQHZi3k665w" +
                "mShg7pw8HFkr_Fea4nzimditNTFRhW3K" +
                "MfhqusPDqWJ7K37AvEHDaLULPKBNj24c",
                342
            },
            {
                2048,
                "1234",
                "12345678901234567890123456789012",
                "1234567890123456",
                "MFq4hhLJN8_F6ODUWX20tO4RIJURlMHA" +
                "mdujFMTyqc2Y3zHIXzmaK4CcoThggqZX" +
                "44-4kbhjwk9ihwuzS4GAQuSCCdoh5xzT" +
                "WfeboPu6zE51BrZQdz67VavvmvpHVdGg" +
                "oQcSsa_GiZcc7aBYh-AhfCyHrPb-r1hN" +
                "y_AWXv8hcO8mIS1fJ3Mvtr3Xxfwlydrn" +
                "23YUwuOG-tX4FctKqh2eFFkrht53ZwVv" +
                "7q67U3x774KjbUpB4LbML6APxe4ucghl" +
                "DpY_A_DFLH2GlvvouVaT3jCibkY_yIMC" +
                "1lNSBIdgpKGoAoZWy4bIpqDUu0SiLvDO" +
                "mclpPRARakRr15F21a_MQ9wL_JNwnG1u" +
                "T1zKZNgUcr2GaWk31ahOBKB0lfr-E7W2",
                342
            },
            {
                2048,
                "1234567890123456",
                "12345678901234567890123456789012",
                "1234567890123456",
                "oFqfBVNvWyUYThQiA54V_Lpx6Ka2zqEF" +
                "QCQBxcYhnbG2uuShACbf3I31USwRCFDV" +
                "mBLmfcO4ReMJFQzen-tRRuapOQ4Pjzdp" +
                "IRw_T9wYjj0n3Sjs1NZnDbN3hbHCmXoq" +
                "sl0byi0Lr5hwhmqOCj7Po5ey4EsPpuqb" +
                "tPx38PPae-zOlnMrdYuKhV8jIMDSsslf" +
                "VWMOgUlYnDOt9Pd1NEJkJE-GxYIYyzPB" +
                "_NtxwQf5moDjsNzxtx5fzEejo8BGDQ5Q" +
                "phjkQCBmMWd1fKN3Z3aBSNn_WS2HwxzU" +
                "gl10lzaHityP9iZU2DY8qkQB_wSk7-pf" +
                "h05CITq0DPIOHDQzVkcWlnuUZ55SZL-E" +
                "BpxoZDMH74B7GmHK66rSGH0MoSGY1fZC" +
                "hAWyjRKa0nWslBVkLoJRUg",
                342
            },
            {
                4096,
                "1234567890123456",
                "12345678901234567890123456789012",
                "1234567890123456",
                "rqA8g_yyA0eeLoun6rqnUxgy3JnIS9p8" +
                "bAgZYf4774ZahHcFCOozwWbMU_0HVMS9" +
                "sOlAmr-dQl6RqDaOLfAxrHq3mluFSlXf" +
                "gcJXrvPtf27u_4NCHXuwm825ptpmprPx" +
                "wl0z4tz6u-fqNBSfQuHApZ3MvAGsEa0v" +
                "b0IftBX0q8tKL6sdCx6WpTGcynEdxLcZ" +
                "Tx6cM4LRdcjL3SQZ5vk4VF69lS2r1WgJ" +
                "h8eUa_VwgsqhTkoc7wJAECqxHBQSh6q-" +
                "GOt6bpVnlaGkM_BfcrB5SJdtcEZd5BgG" +
                "xG8QwQGwsT60jErxpd5rYLfBrG7kgVse" +
                "yksfN-99-kUHQpkwCIS_zS5bpr3hLpBi" +
                "UhSA4638Xgd2qyAZCgl3OBY56HSdncZq" +
                "5o4xGycM69eN5hb-c852W-dP6S49BXSn" +
                "3OpmEOkZoIeNw0EYHpLLpfaLwafIVdLC" +
                "bQZX1g_szDcBDyyM-PN5-jnuaqySRywF" +
                "rMj56U9vAvwtFMaHKY-ll4Qxf8PgoDWM" +
                "7KogGgkztlZ0ZzaMwBLQeTDpjbNl5NXJ" +
                "CxobJfGv8w6zQZmDz8J2K3DsQrDmZid_" +
                "W6Gtsv7XsSnY-gl6TD4IkK1VEKnttqXa" +
                "PfVdCNadtQ-Z1INiK2pa3F0NKs4POO-K" +
                "PpW68kQ5l2qeUAVv6B-QdcwunyMh9XO_" +
                "vGx8Wf8SrbZ7lGeeUmS_hAacaGQzB--A" +
                "exphyuuq0hh9DKEhmNX2QoQFso0SmtJ1" +
                "rJQVZC6CUVI",
                684
            }
        };
    }

    @Test(dataProvider = "specVectorData")
    public void testSpecVectorsEncryption(
        final int bits,
        final String data,
        final String key,
        final String iv,
        final String encrypted,
        final int rsaLength
    )
        throws Throwable
    {
        AsymmetricBlockCipher rsaCipher = new OAEPEncoding(
            new RSAEngine(),
            new SHA1Digest()
        );
        BufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new PKCS7Padding()
        );
        SecureRandom random = Mockito.mock(SecureRandom.class);
        Mockito.when(random.generate(32)).thenReturn(key.getBytes(Charset.forName("US-ASCII")));
        Mockito.when(random.generate(16)).thenReturn(iv.getBytes(Charset.forName("US-ASCII")));
        this.encryptionCipher = new EncryptionCipher(
            new Base64UriCodec(),
            rsaCipher,
            aesCipher,
            new SHA1Digest(),
            random
        );
        PrivateKey privateKey = this.keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream(String.format("pem/rsa-%d-nopass.private.pem", bits))
        );
        String actualEncrypted = this.encryptionCipher.encrypt(privateKey, data);

        Assert.assertEquals(actualEncrypted.substring(rsaLength), encrypted.substring(rsaLength));
    }

    @Test(dataProvider = "specVectorData")
    public void testSpecVectorsDecryption(
        int bits,
        String data,
        String key,
        String iv,
        String encrypted,
        int rsaLength
    )
        throws Throwable
    {
        PrivateKey privateKey = this.keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream(String.format("pem/rsa-%d-nopass.private.pem", bits))
        );
        String decrypted = this.cipher.decrypt(privateKey, encrypted);

        Assert.assertEquals(decrypted, data);
    }

    @Test
    public void testEncryptDecryptWithGeneratedKey() throws Throwable
    {
        PrivateKey privateKey = this.keyFactory.generatePrivateKey();
        String encrypted = this.cipher.encrypt(privateKey, "foobar");
        String decrypted = this.cipher.decrypt(privateKey, encrypted);

        Assert.assertEquals(decrypted, "foobar");
    }

    @Test
    public void testEncryptDecryptWithLargeGeneratedKey() throws Throwable
    {
        PrivateKey privateKey = this.keyFactory.generatePrivateKey(4096);
        String encrypted = this.cipher.encrypt(privateKey, "foobar");
        String decrypted = this.cipher.decrypt(privateKey, encrypted);

        Assert.assertEquals(decrypted, "foobar");
    }

    @Test
    public void testDocumentationSyntaxGeneratingKeys()
    {
        KeyFactory keyFactory = new KeyFactory();

        PrivateKey privateKey = keyFactory.generatePrivateKey();
        /* System.out.println( */ privateKey.toPem(); // ); // outputs the key in PEM format
        /* System.out.println( */ privateKey.toPem("password"); // ); // outputs the key in encrypted PEM format

        PublicKey publicKey = privateKey.publicKey();
        /* System.out.println( */ publicKey.toPem(); // ); // outputs the key in PEM format
    }

    @Test
    public void testDocumentationSyntaxEncrypting()
    {
        String data = "Super secret data.";

        KeyFactory keyFactory = new KeyFactory();
        PrivateKey key;
        try {
            key = keyFactory.createPrivateKey(new File(this.exampleKeyFileUri), "password");
        } catch (PrivateKeyReadException e) {
            throw new RuntimeException("MISSION ABORT!", e); // this could be handled much better...
        }

        EncryptionCipher cipher = new EncryptionCipher();
        String encrypted = cipher.encrypt(key, data);
    }

    @Test
    public void testDocumentationSyntaxEncryptingMultiple()
    {
        String[] data = new String[] {
            "Super secret data.",
            "Extra secret data.",
            "Mega secret data."
        };

        KeyFactory keyFactory = new KeyFactory();
        PrivateKey key;
        try {
            key = keyFactory.createPrivateKey(new File(this.exampleKeyFileUri), "password");
        } catch (PrivateKeyReadException e) {
            throw new RuntimeException("MISSION ABORT!", e); // this could be handled much better...
        }

        BoundEncryptionCipher cipher = new BoundEncryptionCipher(key);

        String[] encrypted = new String[data.length];
        for (int i = 0; i < data.length; ++i) {
            encrypted[i] = cipher.encrypt(data[i]);
        }
    }

    @Test
    public void testDocumentationSyntaxDecrypting()
    {
        String encrypted = "<some encrypted data>";

        KeyFactory keyFactory = new KeyFactory();
        PrivateKey key;
        try {
            key = keyFactory.createPrivateKey(new File(this.exampleKeyFileUri), "password");
        } catch (PrivateKeyReadException e) {
            throw new RuntimeException("MISSION ABORT!", e); // this could be handled much better...
        }

        DecryptionCipher cipher = new DecryptionCipher();

        String data;
        try {
            data = cipher.decrypt(key, encrypted);
        } catch (DecryptionFailedException e) {
            // decryption failed
        }
    }

    @Test
    public void testDocumentationSyntaxDecryptingMultiple()
    {
        String[] encrypted = new String[] {
            "<some encrypted data>",
            "<more encrypted data>",
            "<other encrypted data>"
        };

        KeyFactory keyFactory = new KeyFactory();
        PrivateKey key;
        try {
            key = keyFactory.createPrivateKey(new File(this.exampleKeyFileUri), "password");
        } catch (PrivateKeyReadException e) {
            throw new RuntimeException("MISSION ABORT!", e); // this could be handled much better...
        }

        BoundDecryptionCipher cipher = new BoundDecryptionCipher(key);

        String[] data = new String[encrypted.length];
        for (int i = 0; i < encrypted.length; ++i) {
            try {
                data[i] = cipher.decrypt(encrypted[i]);
            } catch (DecryptionFailedException e) {
                // decryption failed
            }
        }
    }

    private EncryptionCipher encryptionCipher;
    private DecryptionCipher decryptionCipher;
    private Cipher cipher;
    private KeyFactory keyFactory;
    private URI exampleKeyFileUri;
}
