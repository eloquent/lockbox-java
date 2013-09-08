/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox;

import co.lqnt.lockbox.exception.DecryptionFailedException;
import co.lqnt.lockbox.key.KeyFactory;
import co.lqnt.lockbox.key.PrivateKey;
import co.lqnt.lockbox.util.SecureRandom;
import co.lqnt.lockbox.util.codec.Base64UriCodec;
import java.nio.charset.Charset;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class CipherTest
{
    public CipherTest() throws Throwable
    {
        this.encryptionCipher = new EncryptionCipher();
        this.decryptionCipher = new DecryptionCipher();
        this.cipher = new Cipher(this.encryptionCipher, this.decryptionCipher);

        this.keyFactory = new KeyFactory();
        this.key = this.keyFactory.createPrivateKey(
            this.getClass().getClassLoader().getResourceAsStream("pem/rsa-2048-nopass.private.pem")
        );
        this.rsaCipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        this.aesCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        this.base64UriCodec = new Base64UriCodec();
        this.aesCipherBadPadding = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new AESEngine()),
            new ZeroBytePadding()
        );
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.cipher.encryptionCipher(), this.encryptionCipher);
        Assert.assertSame(this.cipher.decryptionCipher(), this.decryptionCipher);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.cipher = new Cipher();

        Assert.assertSame(this.cipher.encryptionCipher().getClass(), EncryptionCipher.class);
        Assert.assertSame(this.cipher.decryptionCipher().getClass(), DecryptionCipher.class);
    }

    @DataProvider(name = "encryptedData")
    public Object[][] encryptedData()
    {
        StringBuilder longData = new StringBuilder(8192);
        for (int i = 0; i < 8192; ++i) {
            longData.append('A');
        }

        return new Object[][]{
            {""},
            {"foobar"},
            {longData.toString()}
        };
    }

    @Test(dataProvider = "encryptedData")
    public void testEncryptDecrypt(String data) throws Throwable
    {
        byte[] encrypted = this.cipher.encrypt(this.key, data.getBytes(Charset.forName("US-ASCII")));
        byte[] decrypted = this.cipher.decrypt(this.key, encrypted);

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), data);
    }

    @Test(dataProvider = "encryptedData")
    public void testEncryptPublic(String data) throws Throwable
    {
        byte[] encrypted = this.cipher.encrypt(this.key.publicKey(), data.getBytes(Charset.forName("US-ASCII")));
        byte[] decrypted = this.cipher.decrypt(this.key, encrypted);

        Assert.assertEquals(new String(decrypted, Charset.forName("US-ASCII")), data);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testEncryptFailureRsa() throws Throwable
    {
        AsymmetricBlockCipher mockRsaCipher = Mockito.mock(AsymmetricBlockCipher.class);
        Mockito.when(mockRsaCipher.processBlock(Mockito.any(byte[].class), Mockito.anyInt(), Mockito.anyInt()))
            .thenThrow(new InvalidCipherTextException());
        this.encryptionCipher = new EncryptionCipher(
            this.base64UriCodec,
            mockRsaCipher,
            this.aesCipher,
            new SHA1Digest(),
            new SecureRandom()
        );

        this.encryptionCipher.encrypt(this.key, new byte[0]);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testEncryptFailureAesCipherText() throws Throwable
    {
        BufferedBlockCipher mockAesCipher = Mockito.mock(BufferedBlockCipher.class);
        Mockito.when(mockAesCipher.doFinal(Mockito.any(byte[].class), Mockito.anyInt()))
            .thenThrow(new InvalidCipherTextException());
        this.encryptionCipher = new EncryptionCipher(
            this.base64UriCodec,
            this.rsaCipher,
            mockAesCipher,
            new SHA1Digest(),
            new SecureRandom()
        );

        this.encryptionCipher.encrypt(this.key, new byte[0]);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testEncryptFailureAesDataLength() throws Throwable
    {
        BufferedBlockCipher mockAesCipher = Mockito.mock(BufferedBlockCipher.class);
        Mockito.when(mockAesCipher.doFinal(Mockito.any(byte[].class), Mockito.anyInt()))
            .thenThrow(new DataLengthException());
        this.encryptionCipher = new EncryptionCipher(
            this.base64UriCodec,
            this.rsaCipher,
            mockAesCipher,
            new SHA1Digest(),
            new SecureRandom()
        );

        this.encryptionCipher.encrypt(this.key, new byte[0]);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureNotBase64() throws Throwable
    {
        this.cipher.decrypt(this.key, "foo:bar".getBytes(Charset.forName("US-ASCII")));
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureBadData() throws Throwable
    {
        this.cipher.decrypt(this.key, "foobar".getBytes(Charset.forName("US-ASCII")));
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureEmptyKey() throws Throwable
    {
        byte[] encrypted = this.base64UriCodec.encode(this.encryptRsa(this.key, new byte[0]));

        this.cipher.decrypt(this.key, encrypted);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureEmptyKeyTooShort() throws Throwable
    {
        byte[] encrypted = this.base64UriCodec.encode(
            this.encryptRsa(this.key, "1".getBytes(Charset.forName("US-ASCII")))
        );

        this.cipher.decrypt(this.key, encrypted);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureEmptyIv() throws Throwable
    {
        byte[] encrypted = this.base64UriCodec.encode(
            this.encryptRsa(this.key, "12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII")))
        );

        this.cipher.decrypt(this.key, encrypted);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureBadAesData() throws Throwable
    {
        byte[] encryptedKeyAndIv = this.encryptRsa(
            this.key,
            "123456789012345678901234567890123456789012345678".getBytes(Charset.forName("US-ASCII"))
        );
        byte[] encrypted = new byte[encryptedKeyAndIv.length + 6];
        System.arraycopy(encryptedKeyAndIv, 0, encrypted, 0, encryptedKeyAndIv.length);
        System.arraycopy("foobar".getBytes(Charset.forName("US-ASCII")), 0, encrypted, encryptedKeyAndIv.length, 6);
        byte[] encryptedEncoded = this.base64UriCodec.encode(encrypted);

        this.cipher.decrypt(this.key, encryptedEncoded);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureBadAesPadding() throws Throwable
    {
        byte[] generatedKey = "12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII"));
        byte[] iv = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        byte[] keyAndIv = new byte[48];
        System.arraycopy(generatedKey, 0, keyAndIv, 0, 32);
        System.arraycopy(iv, 0, keyAndIv, 32, 16);
        byte[] encryptedKeyAndIv = this.encryptRsa(this.key, keyAndIv);
        byte[] encryptedData = this.encryptAesBadPadding(
            generatedKey,
            iv,
            "foobar".getBytes(Charset.forName("US-ASCII"))
        );
        byte[] encrypted = new byte[encryptedKeyAndIv.length + encryptedData.length];
        System.arraycopy(encryptedKeyAndIv, 0, encrypted, 0, encryptedKeyAndIv.length);
        System.arraycopy(encryptedData, 0, encrypted, encryptedKeyAndIv.length, encryptedData.length);
        byte[] encryptedEncoded = this.base64UriCodec.encode(encrypted);

        this.cipher.decrypt(this.key, encryptedEncoded);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureShortHash() throws Throwable
    {
        byte[] generatedKey = "12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII"));
        byte[] iv = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        byte[] keyAndIv = new byte[48];
        System.arraycopy(generatedKey, 0, keyAndIv, 0, 32);
        System.arraycopy(iv, 0, keyAndIv, 32, 16);
        byte[] encryptedKeyAndIv = this.encryptRsa(this.key, keyAndIv);
        byte[] encryptedData = this.encryptAes(
            generatedKey,
            iv,
            "foobar".getBytes(Charset.forName("US-ASCII"))
        );
        byte[] encrypted = new byte[encryptedKeyAndIv.length + encryptedData.length];
        System.arraycopy(encryptedKeyAndIv, 0, encrypted, 0, encryptedKeyAndIv.length);
        System.arraycopy(encryptedData, 0, encrypted, encryptedKeyAndIv.length, encryptedData.length);
        byte[] encryptedEncoded = this.base64UriCodec.encode(encrypted);

        this.cipher.decrypt(this.key, encryptedEncoded);
    }

    @Test(expectedExceptions = DecryptionFailedException.class)
    public void testDecryptFailureBadHash() throws Throwable
    {
        byte[] generatedKey = "12345678901234567890123456789012".getBytes(Charset.forName("US-ASCII"));
        byte[] iv = "1234567890123456".getBytes(Charset.forName("US-ASCII"));
        byte[] keyAndIv = new byte[48];
        System.arraycopy(generatedKey, 0, keyAndIv, 0, 32);
        System.arraycopy(iv, 0, keyAndIv, 32, 16);
        byte[] encryptedKeyAndIv = this.encryptRsa(this.key, keyAndIv);
        byte[] hashAndData = "12345678901234567890foobar".getBytes(Charset.forName("US-ASCII"));
        byte[] encryptedData = this.encryptAes(
            generatedKey,
            iv,
            hashAndData
        );
        byte[] encrypted = new byte[encryptedKeyAndIv.length + encryptedData.length];
        System.arraycopy(encryptedKeyAndIv, 0, encrypted, 0, encryptedKeyAndIv.length);
        System.arraycopy(encryptedData, 0, encrypted, encryptedKeyAndIv.length, encryptedData.length);
        byte[] encryptedEncoded = this.base64UriCodec.encode(encrypted);

        this.cipher.decrypt(this.key, encryptedEncoded);
    }

    protected byte[] encryptRsa(PrivateKey key, byte[] data) throws Throwable
    {
        this.rsaCipher.init(true, key.publicKey().bcKeyParameters());

        return this.rsaCipher.processBlock(data, 0, data.length);
    }

    protected byte[] encryptAes(byte[] key, byte[] iv, byte[] data) throws Throwable
    {
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), iv);

        this.aesCipher.reset();
        this.aesCipher.init(true, parameters);

        int outputSize = this.aesCipher.getOutputSize(data.length);
        byte[] decrypted = new byte[outputSize];

        int length = this.aesCipher.processBytes(data, 0, data.length, decrypted, 0);
        length += this.aesCipher.doFinal(decrypted, length);

        return Arrays.copyOfRange(decrypted, 0, length);
    }

    protected byte[] encryptAesBadPadding(byte[] key, byte[] iv, byte[] data) throws Throwable
    {
        CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), iv);

        this.aesCipherBadPadding.reset();
        this.aesCipherBadPadding.init(true, parameters);

        int outputSize = this.aesCipherBadPadding.getOutputSize(data.length);
        byte[] decrypted = new byte[outputSize];

        int length = this.aesCipherBadPadding.processBytes(data, 0, data.length, decrypted, 0);
        length += this.aesCipherBadPadding.doFinal(decrypted, length);

        return Arrays.copyOfRange(decrypted, 0, length);
    }

    private EncryptionCipher encryptionCipher;
    private DecryptionCipher decryptionCipher;
    private Cipher cipher;
    private KeyFactory keyFactory;
    private PrivateKey key;
    private AsymmetricBlockCipher rsaCipher;
    private BufferedBlockCipher aesCipher;
    private BufferedBlockCipher aesCipherBadPadding;
    private Base64UriCodec base64UriCodec;
}
