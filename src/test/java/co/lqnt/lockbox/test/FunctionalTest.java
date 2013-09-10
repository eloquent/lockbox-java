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
                "FzFcxXm57XqDzsZm4vVUaspsK1-Hcw7fN" +
                "jAqadl-WhwR_Kfwv4gM7v7OnDGWfpDOTl" +
                "I_nlQvvwP3TP98tOhyrsJkpDDMZ0WSQVP" +
                "cl23xTk6xbLvwl2qRVdZa8isKCXXcuKt5" +
                "XIv1Mexp2Dzyn8w8TNYOdK0EiNj1v2PUk" +
                "7X2QUPvK0poT_3fUlN13aK28KBqg-CGw0" +
                "xzsGSG4k7CN8FEfGqbSBfuNxumH0eJyzZ" +
                "1s4cYbcn3OWdlQln7asp21WZHj7SEMWIf" +
                "dsrtoWL85uEAnLxYG_CXD1nteVXffAwFv" +
                "ByMT1UmNQ0AWjm8KJiH8hLXPr09rbo5Vz" +
                "s6c5lSrjMmM9itNTFRhW3KMfhqusPDqWJ" +
                "7K37AvEHDaLULPKBNj24c",
                342
            },
            {
                2048,
                "1234",
                "12345678901234567890123456789012",
                "1234567890123456",
                "wdPXCy5amuY7U8tGD0M-nnK5LGc4DC1h" +
                "VwvNWVLCyqOMHgDF3fpsY-8MQkMUuI0T" +
                "eNoutU-TpuGsm6D-KIXeAaWIYuUAaNZ-" +
                "V_5WwmRFT5BEyhQwZ3PFybrs39o4sAlO" +
                "d5IVvLNMMgwRD-FmQc8KU10d3KDd71wW" +
                "r50y7R33xTnyJplx9uqcOrB6ooQLjFcF" +
                "bFU87YPnhkxZK5JryTxAlaDJjfFs-3XM" +
                "zgoJ35rpBgDVywPXbye1C8u5gw81awid" +
                "Xgei_a27MZog1lUvETzMXqqZ4VlhckDV" +
                "m71f4TLMKHTz-CmYinvzj7G_pYmvtHeh" +
                "uxDzjdrT4lbetTuESm-YHKtq9JEj6E2S" +
                "ER4TURlVKf14sPeDgRUo88-zvM7BWpMv",
                342
            },
            {
                2048,
                "1234567890123456",
                "12345678901234567890123456789012",
                "1234567890123456",
                "umvbDKEQtKldCN15bgyGyLm5K5LEDNGJ" +
                "kXbyYask_sgSi9lkGa5ByDZKVs1SMgp0" +
                "mif4GDfyg5xVadsPzoH9-jdSoTB7pNxz" +
                "ns8CNP8KIWEcU6TATwjbW9bP5FBQKxRO" +
                "OTHdLLJ7ADqvuT0QxH1Yy1xzlVGXUXxk" +
                "coMBey_CxiboqjLm_cEl1dA0HyidgxTn" +
                "rArsM7porZPj__gbWIEv58L0S2xv11YL" +
                "0IQMGkQiupJhHKiyAIH4KchZ8whV_aAZ" +
                "193U7toEJ7Ojd7uu6hzMiVDCIRPDa5Ek" +
                "zyBFoNsr2hcTFcU4oxBkRbUottvH9Dji" +
                "SxIPU4O8vomXpUqWzneJ4CBlVmSYgUJa" +
                "4zsJUnll4lufFRTYTYjuCgQhunOAIVS2" +
                "DxuQH8bSZZrHKNIghc0D3Q",
                342
            },
            {
                4096,
                "1234567890123456",
                "12345678901234567890123456789012",
                "1234567890123456",
                "XncYhc3C20kG5Zb8VPB0OGBik6N6a6JY" +
                "333Hz6VN3lQ21xMoc16XW0873AzuyvDI" +
                "YAjNzN0pAQo0CosedUptYLLwRtGrsfUr" +
                "XIZxteHNZ7JiEXGZ8W_6bz9jlbnpfNdH" +
                "GxaR-aePTZWSbyPyPdQysGJlqclXJb_K" +
                "dKfqGHLYOf0LO93kvljQ4ccux18vm8PQ" +
                "GIeAH-L5qMfzfOHzcCXbVU746pZf7mNR" +
                "uIEgfp0AM-JEKItYTIZxr8kP7-WlVDf0" +
                "7cjQkZuUEQ7d9FQLKOWviuQ-PQd2enwI" +
                "MYo3btEiu2XHmUcZEcI2esz_vwBGxHNM" +
                "HGrshgpuP_EvPPR_1EogS2EGHs0l_owU" +
                "hHx4V8LvgMBnO3O2nO9p2WA7ZKH1zMZU" +
                "gGaxMAlZrMweaGvEcke2nwnfLUBVytYd" +
                "QNOBV7TmJ3XMXwgpavZ2eKvVXUpdKfcm" +
                "fsGDxjkJRN8BqDTrSZZmSKZe9VZkGSNS" +
                "99jF9BEa6dmy7RTLy3xSaWdPwbElX3pA" +
                "pgQR5BKHz6DP5p86gaQITelAMMYaZQK3" +
                "tNvW6ncRfJGlD3ax_TezCOtrEmlzVCRe" +
                "OsbK51H_xfST_0PO-hXG35NIGC1vDV8r" +
                "iDMr47HbRIFwm9NxT1VR0hDF0LbIIbkS" +
                "YucMkD_Zv9JjoL4FX0rM0T0fvDJBeJXw" +
                "Zt1ifDOvWxogZVZkmIFCWuM7CVJ5ZeJb" +
                "nxUU2E2I7goEIbpzgCFUtg8bkB_G0mWa" +
                "xyjSIIXNA90",
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
