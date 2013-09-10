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
import co.lqnt.lockbox.util.BcKeyParametersFactory;
import co.lqnt.lockbox.util.PemParserFactory;
import co.lqnt.lockbox.util.SecureRandom;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.Charset;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class KeyFactoryTest
{
    @BeforeMethod
    public void setUp()
    {
        BouncyCastleProvider provider = new BouncyCastleProvider();

        this.pemParserFactory = new PemParserFactory();
        this.bcPublicKeyParametersFactory = new BcKeyParametersFactory();

        this.pemDecryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();
        this.pemDecryptorProviderBuilder.setProvider(provider);

        this.pkcs8DecryptorProviderBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
        this.pkcs8DecryptorProviderBuilder.setProvider(provider);

        this.keyConverter = new JcaPEMKeyConverter();
        this.keyConverter.setProvider(provider);

        this.keyGenerator = new RSAKeyPairGenerator();

        this.random = new SecureRandom();

        this.factory = new KeyFactory(
            this.pemParserFactory,
            this.bcPublicKeyParametersFactory,
            this.pemDecryptorProviderBuilder,
            this.pkcs8DecryptorProviderBuilder,
            this.keyGenerator,
            this.random
        );

        this.privateKeyString =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,C993FE1F47B61753\n" +
            "\n" +
            "YEyAqkV+1qDThx1TYeAEs7eQmT8FkEWv/mnZvebKz3hMweP8/59vGYHzqK6fapGj\n" +
            "WV+UM01IqQQOgsbXdsqn1TyNsOu1QvqLJHQoxkirknAsPfqHHhFCxd0qjY9wW5rp\n" +
            "j29P5SBH+lpizLWa9spjrZuzejI5vDztojy7IJmTu5nsUq1HjyLuhZqBX/JcwDFS\n" +
            "/EGPVPKZcn4bQGUVJ/y1TZIBXkaR8wflVD7ViRh+GrdTjI7biX7LgoY7v0scV25L\n" +
            "NxV/thpxnZEeT5vOeROrPig+aH5VzwimzZ5MSLoCkE0EMJVhrA8xiylIiqw/5xFt\n" +
            "UDWc7DUUGL3OwAEg3EN46vSfgN8tZrFEyoU5//JutZq89few2GbAtyC9sTIxYBxP\n" +
            "1SAc46SM3cHf7MOyuNA4fOceLW3RY6k6GcH9SIBGk49+UWf4TBJg53+Lwj7M57os\n" +
            "o3mg0RtZ1j5snjd8rXKwvTfRMeY70minkPK6RCUwu/aGI9ORGTCOF5FBUXeEEtEC\n" +
            "vgx1mNUjfUK682Q+yjZ3oSMn9pupiGu49XkClxn613be9b/gpKm4Qr62sac/2Y/n\n" +
            "A+zQA4+wevz/zCCoGiktO6AtvIXnuZxGlq4IjzBtYH2D0Z6HatsWWw+LnAeYzSgh\n" +
            "WM/0WjMuiSyYAIQJyqojdIQG+5jwz1WL9mACi8/2r+E1SXcy69ILJn2oWyYLVXD8\n" +
            "vLLK8gV+uKSvmSV2JHYOsuZUGBwyZ75qdY88IaENZTPpZGozh61/mI59seQQqsmZ\n" +
            "T2UD1DiMZZy+/8TW/rpBqiNN8p7Ft/U/OAT2B5j04LIEszMWIJ4ffYF69Xtd/oPU\n" +
            "0p460C1RGxwIhg5bHwfx7w2tEEuM0huBjn9iyaEpJo/YkJpRwGiTi2Xc3Mw5Y2BG\n" +
            "8hdxOvLOpjjGUKjms6QVRqLX2g9hGT5OCKzec4y2Oz9k2aaQ3VCg3fsvlOfP0Yv9\n" +
            "Sh+qJlG66BnrhQ4MMaEbYXpmgp0O4q00+xbInNI83e+Oo3Ia0Oyn6Kbi/4IMaegK\n" +
            "ocH5zr9ONBcUQsibQqu/6b0dSe8Yf2isUtagkFic7ZDsuMmrkmln2PrCBFB2daa8\n" +
            "yWrtZnib9Q2e3QPgFR75kggAmQoN41Y8O2eqw0lHOwBhckE+tSsKkF6dDDyillbB\n" +
            "8XaTllLk2kdC5VGlJtAHGcXDdTgBjyZzbJWt6niJT6KRTWIR6JQk/9t/twmmB9Sr\n" +
            "jXOtCh3/kEDfV+hOFCNNm+mhQdVt8OlevtYnNu3A1sAXpf4Vr3oeaNnvwkqmzlDj\n" +
            "2pbBd7LiJcnP0VvzxSCrErxMBl6s14u2cd5c3r/fiGnaR3u8nxA+GpUPDjD6lNh5\n" +
            "or6BubNGS4NQMrMQ2OL31d5P3qcPZtQoJNdz1MAj5y4qOQBKA384VdIDDF8gJl4k\n" +
            "j5zYqI0tn06/UKWyN3aBknXBKY//LwFBbksSdAeLeHClnbfxpz0hTlj31IT8Td9U\n" +
            "MHgOFCXFKwkUDZH8pou/7Q4eYWwICCcaPp3QA0wv3FNwyBmgamw7quqbk7xiJuz7\n" +
            "1E/yfdAXEjlPRibVjvwpopYitZcGqIS0Mt9bXtwugzdeQh9TF2karA==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        this.publicKeyString =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwpFuTp1Y+b1JZ9k37aJO\n" +
            "7DT7KT6CE426qbH0SmqUmIFCJOxLTnK/tUV/00VMm16XPeOLQwIGAL5+RpcjIQA8\n" +
            "VEgZKvJQ4bPlRTIm/SKP0goCzUbP7hUbtuaUQvXFrrlcl4YRoF2bwbp3BR3ikUE8\n" +
            "ir6ZtiCTJYSawFZQiSq++M/u4ZZ9rYS9OF7NEKDW7bb9SYsHJv4fPlm7hwIWADdj\n" +
            "OdJSsQRVNOoBBOWG8leIPBdlmKq7PaTJlTlgYpW8IIc37LYj5APl26OLWEYI/VQH\n" +
            "HPIE5o9vqKJL0mC0TCrlJv9Z+Bx1408YwFJf32ubc5c0TtvWC9s+8eu+J5bDbzGd\n" +
            "IQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";
        this.privateKeyStringNoPassword =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEAy8jsljdxzsgvboCytmlH3Q03v30fPTNfMqmz2Yn0GdtkqQH0\n" +
            "1+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5VjCl1V9PYeM6Q30PK6411fJexjYA\n" +
            "/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy8G2eqXBbP6dEZFnO0V274TRTB3SL\n" +
            "KD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk1er2i3ldyNIG8vMGv7Iagup69yBr\n" +
            "t8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe+0ejS4eMyziaH7J52XX1rDFreinZ\n" +
            "ZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/vQIDAQABAoIBAAlqWyQFo8h+D1L3\n" +
            "t0oeSye3eJ/sVAkr2nYoyRp/+TtIm7oDUSC4XFWPvo+L/Jj7X+5F2NuIqkraiJcD\n" +
            "Q/RwicylqsPVB4HqUcLUgGLwRaSA8kgOLrWFFBxLC0BBi5/JPZw7L7e85ssFePvP\n" +
            "TAHSLUJWjkId4tlqDQrl61xZDFk3UHawcovZeUp4RAqULeLDXAQTQJYXE8erPjhQ\n" +
            "Y0uSWORe1S1ICaI2aqbjmIHFUzPlz45KlakzLwn4tobeiKeNaHrPw++JMXNVSlPk\n" +
            "hGxPliXbZauaoDHa/p6w3hDvr2ZjOLU7QDHgdiWZ4EUW5AQRf7aiKtE2yNPTGJQb\n" +
            "yv9QHzECgYEA/UQluesABp+UJvvDzbEmDkipgCbEu5fHyGb8C0FPZET1ys2wu0DI\n" +
            "IaYR4hiYetrv5inHzXnMSkuQSMzPa+SyBXgiGnB9J2+sBX0H9byq3QuMriTSDQPA\n" +
            "ptxZlYAXTEXRUsNYG3/VCiC75VjbufHI7QmsOStTij6w15gchTrBt+cCgYEAzfwL\n" +
            "amiGmgVblJ1xr+8zwZMv99c22j8K+Cm4PoUhQ6I6XcgqHyDj8mD65UxQU3aE8R2m\n" +
            "vbX7XW1jrpflbVwoRoJS9z8F77rm6t38yS3WJqz6kyoQ0u4W2m8D8g/WWROjeGFD\n" +
            "ljrpiwErkmzCGrNhSk4O9YTXrNUGkD5MTpVPBrsCgYBlmdgUnIy3G3+AoBFty/o7\n" +
            "UrUE3wifRQV1hLLqBPpHfE6qXBfhFtzyer/D1yAccQY6bFpmOM1WpLeuLNOtMeKk\n" +
            "xQvRVX0vu+HjlcQCtfxJjt+R4N2PMQkxJ0ac7fTquTt/GzSWW5LobDdUi3AiSTfU\n" +
            "t8Oqb5Ik7H9fDfurCuY50wKBgQDDC/wfSVTTeWlLo35oct+WV/JfA7ocFQAlFxQw\n" +
            "l011RqNv9D72dOWDuJM7FvUk4yBlVId0MmMQB6oRRCHqWQ6GHZfEKThM1bUdBxD7\n" +
            "ytxyiO9I9NczdGHNervItXhppq/vKGKgWa6VgokowLVYJS1l994wXBcBwEHTyjnl\n" +
            "W3qWSwKBgQDZo0uMMWevRBriPT6OCdEYwnOZOMvh6LdXG2wyC2wYMY+8XOMzDrZP\n" +
            "zD3i4wQYCfJg7pyhVtctBz2NQ8J878xm2EXzUpGaIxjLIXb1UVgw4XXcM7LkjFaa\n" +
            "J1iMrMTLGSX89+gW3Bg8hxS7klxZf7ZlVSzLpA2jkK3k5vdgWGVhtA==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        this.publicKeyStringNoPassword = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8jsljdxzsgvboCytmlH\n" +
            "3Q03v30fPTNfMqmz2Yn0GdtkqQH01+H9y5bWWCQyeGOATvIPrELGeB9nRlQeaTb5\n" +
            "VjCl1V9PYeM6Q30PK6411fJexjYA/UbRG/9I/K+A9UBfJvUsjGVUMxZR8n8jmmSy\n" +
            "8G2eqXBbP6dEZFnO0V274TRTB3SLKD2tfYBYwMtXqT+rSbH1OyoS29A03FaUgkRk\n" +
            "1er2i3ldyNIG8vMGv7Iagup69yBrt8xo61IFj76dkocbozp1Y4SGzyjkR/ukRSLe\n" +
            "+0ejS4eMyziaH7J52XX1rDFreinZZDoE571ameu0biuM6aT8P1pk85VIqHLlqRm/\n" +
            "vQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";
        this.privateKeyStringPkcs8 = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
            "MIIE6TAbBgkqhkiG9w0BBQMwDgQIv2lN8R4qMeUCAggABIIEyPIkq+bUvclc9c9b\n" +
            "6WCfySC2k+rSe/ZXUhY6+YdhquWKE4or/k3OFDGMA0JjGZFCUn7wgrxdg9RQ1mzV\n" +
            "aUqatTaSsv8H7yGj90MoVNlDvhBUfh3yRv5kHXwsAQNBivEMBzF0uxKGgCzMdgee\n" +
            "+ieTc818psXtWsVWTvAreZOPGWhMuBRy8Ze+da+qtp7o3RWY/bMMBl6b9zRvzgJM\n" +
            "PU7iyqYV9Rxvrfq9XIHeXkSBpsfokr044M8OOQQSbkCah68QZJz1VGxngaCfJWQ8\n" +
            "9fW/XJOVjEgpaKYFP+CWLN9hQVSiz5th29/hQYCJuU5Xm66NdaYi1lv69zYnwiGU\n" +
            "iDHgMHFfuVXYMcSy1RUKjIAnspqinloltm0BGgH9nC1ZN/04KSKWAOBHbqZTBcoz\n" +
            "tI69GrNF/3x+Ss2vK08gMGuJbfxE5ECh/kUVjsWgD6H6aKxe+rluF5iCHSwETURg\n" +
            "67j1eC7mzNAyHKygLnW1Fmnq07sEKGFq/ONUz5Cvlepf6WxwaAMX4NPjxfBHJkZG\n" +
            "zmRiJiQdXnsjDTsBAgeFVZgM6X57RQyHJRnrDkikW/68b9pm8CDEMOo07wzJkgnw\n" +
            "blwKeVfW4+bPwu6bjMzgWSNHaYD5OGLAOCtQ8FI4mS78WcL2edW6OhI3E6ZGM56i\n" +
            "J5cCHzAAyn/uACgOpUS1O/ATUuzOs5ryFbGXA4GSeTiGPCGMO4cxnagTXD6BUFqC\n" +
            "OYLa2+uR+SmLyuKjv9O9Osj7rqylad/mCpVXsh7crFVkF43gnvz3Fu7/nBV0j/uK\n" +
            "BnKNkF3+gxz77wFWnH6o7oa4XxXlJ1S5ZgTXdj11hX9vricTeMWXoppKJS56RB0J\n" +
            "WdQdD66pPl4w2S9j4aCIDwYk5H/QBL1QgTOO9SsxT0a7q0T9czJMWyQmo8Wo8vJx\n" +
            "x6euGTpM7i3vKENtMjZLROa25XeC2n0RFGxLcfp8clSczG3iWMgicfwAnRqOvfIv\n" +
            "5jp3yqFzH8RTshJXRvYDBgHKHPtal71ksCcf+SIxyjs6+uULTRLp7L/jR3/R4zHg\n" +
            "KZDdVomizSWAjj+R2dmvvuq4IQtPzKd4XSlQA/5YVBjAGWSIGn/UcSsRyKWlIdcP\n" +
            "QkeAMOWLEVa3/2js26DQlm5BLHNlrCO7uhNWH6yy8iFKSVzvCZWMjGaUCMWBUpz6\n" +
            "5nTxLor2Oj3CoWNU0gvIJS/zolVwxBYGtvRIliRNijn/Qoh9rBxiufro3Ji4VRSW\n" +
            "R69mrqB/4OlGveiAjH4iWPWsFQiz2tEqSiAuFgE6pCmZcxA5hLSoSpw+jbcEDrU3\n" +
            "eYWbtKQqnfm28y6Ae74lvaWboVgK2/EEE4vTzk62iFnH2LPucXynlKNaSyG0goRC\n" +
            "k82Z4PILJfha/pFjEocqEXfJ8noVzLZX30OxNjAQ0LhI779MyZA2shYoh0qc+86e\n" +
            "ENU84OG21wHp4xwwxStbt/jbzCz67hjc/iqmvnjLdaooOVCDeUl0yYs81uvAIKvp\n" +
            "j6LhbAFLemlaWVtkOqgQTs1dO1uTFCID21/pQUxnRxDRSEiyRq4a/XAD/FezeLQv\n" +
            "OeQp2EYIQysr8XpbOaPYOW99uFIQCALmJ5a1JJfDDWvcR6crJkjI60B3NirZSR/p\n" +
            "CdU3lo063CcRZy7m3A==\n" +
            "-----END ENCRYPTED PRIVATE KEY-----\n";
        this.privateKeyStringPkcs8NoPassword = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLyOyWN3HOyC9u\n" +
            "gLK2aUfdDTe/fR89M18yqbPZifQZ22SpAfTX4f3LltZYJDJ4Y4BO8g+sQsZ4H2dG\n" +
            "VB5pNvlWMKXVX09h4zpDfQ8rrjXV8l7GNgD9RtEb/0j8r4D1QF8m9SyMZVQzFlHy\n" +
            "fyOaZLLwbZ6pcFs/p0RkWc7RXbvhNFMHdIsoPa19gFjAy1epP6tJsfU7KhLb0DTc\n" +
            "VpSCRGTV6vaLeV3I0gby8wa/shqC6nr3IGu3zGjrUgWPvp2ShxujOnVjhIbPKORH\n" +
            "+6RFIt77R6NLh4zLOJofsnnZdfWsMWt6KdlkOgTnvVqZ67RuK4zppPw/WmTzlUio\n" +
            "cuWpGb+9AgMBAAECggEACWpbJAWjyH4PUve3Sh5LJ7d4n+xUCSvadijJGn/5O0ib\n" +
            "ugNRILhcVY++j4v8mPtf7kXY24iqStqIlwND9HCJzKWqw9UHgepRwtSAYvBFpIDy\n" +
            "SA4utYUUHEsLQEGLn8k9nDsvt7zmywV4+89MAdItQlaOQh3i2WoNCuXrXFkMWTdQ\n" +
            "drByi9l5SnhECpQt4sNcBBNAlhcTx6s+OFBjS5JY5F7VLUgJojZqpuOYgcVTM+XP\n" +
            "jkqVqTMvCfi2ht6Ip41oes/D74kxc1VKU+SEbE+WJdtlq5qgMdr+nrDeEO+vZmM4\n" +
            "tTtAMeB2JZngRRbkBBF/tqIq0TbI09MYlBvK/1AfMQKBgQD9RCW56wAGn5Qm+8PN\n" +
            "sSYOSKmAJsS7l8fIZvwLQU9kRPXKzbC7QMghphHiGJh62u/mKcfNecxKS5BIzM9r\n" +
            "5LIFeCIacH0nb6wFfQf1vKrdC4yuJNINA8Cm3FmVgBdMRdFSw1gbf9UKILvlWNu5\n" +
            "8cjtCaw5K1OKPrDXmByFOsG35wKBgQDN/AtqaIaaBVuUnXGv7zPBky/31zbaPwr4\n" +
            "Kbg+hSFDojpdyCofIOPyYPrlTFBTdoTxHaa9tftdbWOul+VtXChGglL3PwXvuubq\n" +
            "3fzJLdYmrPqTKhDS7hbabwPyD9ZZE6N4YUOWOumLASuSbMIas2FKTg71hNes1QaQ\n" +
            "PkxOlU8GuwKBgGWZ2BScjLcbf4CgEW3L+jtStQTfCJ9FBXWEsuoE+kd8TqpcF+EW\n" +
            "3PJ6v8PXIBxxBjpsWmY4zVakt64s060x4qTFC9FVfS+74eOVxAK1/EmO35Hg3Y8x\n" +
            "CTEnRpzt9Oq5O38bNJZbkuhsN1SLcCJJN9S3w6pvkiTsf18N+6sK5jnTAoGBAMML\n" +
            "/B9JVNN5aUujfmhy35ZX8l8DuhwVACUXFDCXTXVGo2/0PvZ05YO4kzsW9STjIGVU\n" +
            "h3QyYxAHqhFEIepZDoYdl8QpOEzVtR0HEPvK3HKI70j01zN0Yc16u8i1eGmmr+8o\n" +
            "YqBZrpWCiSjAtVglLWX33jBcFwHAQdPKOeVbepZLAoGBANmjS4wxZ69EGuI9Po4J\n" +
            "0RjCc5k4y+Hot1cbbDILbBgxj7xc4zMOtk/MPeLjBBgJ8mDunKFW1y0HPY1Dwnzv\n" +
            "zGbYRfNSkZojGMshdvVRWDDhddwzsuSMVponWIysxMsZJfz36BbcGDyHFLuSXFl/\n" +
            "tmVVLMukDaOQreTm92BYZWG0\n" +
            "-----END PRIVATE KEY-----\n";
        this.privateKeyStringWrongIv =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,C993FE1F47B61754\n" +
            "\n" +
            "YEyAqkV+1qDThx1TYeAEs7eQmT8FkEWv/mnZvebKz3hMweP8/59vGYHzqK6fapGj\n" +
            "WV+UM01IqQQOgsbXdsqn1TyNsOu1QvqLJHQoxkirknAsPfqHHhFCxd0qjY9wW5rp\n" +
            "j29P5SBH+lpizLWa9spjrZuzejI5vDztojy7IJmTu5nsUq1HjyLuhZqBX/JcwDFS\n" +
            "/EGPVPKZcn4bQGUVJ/y1TZIBXkaR8wflVD7ViRh+GrdTjI7biX7LgoY7v0scV25L\n" +
            "NxV/thpxnZEeT5vOeROrPig+aH5VzwimzZ5MSLoCkE0EMJVhrA8xiylIiqw/5xFt\n" +
            "UDWc7DUUGL3OwAEg3EN46vSfgN8tZrFEyoU5//JutZq89few2GbAtyC9sTIxYBxP\n" +
            "1SAc46SM3cHf7MOyuNA4fOceLW3RY6k6GcH9SIBGk49+UWf4TBJg53+Lwj7M57os\n" +
            "o3mg0RtZ1j5snjd8rXKwvTfRMeY70minkPK6RCUwu/aGI9ORGTCOF5FBUXeEEtEC\n" +
            "vgx1mNUjfUK682Q+yjZ3oSMn9pupiGu49XkClxn613be9b/gpKm4Qr62sac/2Y/n\n" +
            "A+zQA4+wevz/zCCoGiktO6AtvIXnuZxGlq4IjzBtYH2D0Z6HatsWWw+LnAeYzSgh\n" +
            "WM/0WjMuiSyYAIQJyqojdIQG+5jwz1WL9mACi8/2r+E1SXcy69ILJn2oWyYLVXD8\n" +
            "vLLK8gV+uKSvmSV2JHYOsuZUGBwyZ75qdY88IaENZTPpZGozh61/mI59seQQqsmZ\n" +
            "T2UD1DiMZZy+/8TW/rpBqiNN8p7Ft/U/OAT2B5j04LIEszMWIJ4ffYF69Xtd/oPU\n" +
            "0p460C1RGxwIhg5bHwfx7w2tEEuM0huBjn9iyaEpJo/YkJpRwGiTi2Xc3Mw5Y2BG\n" +
            "8hdxOvLOpjjGUKjms6QVRqLX2g9hGT5OCKzec4y2Oz9k2aaQ3VCg3fsvlOfP0Yv9\n" +
            "Sh+qJlG66BnrhQ4MMaEbYXpmgp0O4q00+xbInNI83e+Oo3Ia0Oyn6Kbi/4IMaegK\n" +
            "ocH5zr9ONBcUQsibQqu/6b0dSe8Yf2isUtagkFic7ZDsuMmrkmln2PrCBFB2daa8\n" +
            "yWrtZnib9Q2e3QPgFR75kggAmQoN41Y8O2eqw0lHOwBhckE+tSsKkF6dDDyillbB\n" +
            "8XaTllLk2kdC5VGlJtAHGcXDdTgBjyZzbJWt6niJT6KRTWIR6JQk/9t/twmmB9Sr\n" +
            "jXOtCh3/kEDfV+hOFCNNm+mhQdVt8OlevtYnNu3A1sAXpf4Vr3oeaNnvwkqmzlDj\n" +
            "2pbBd7LiJcnP0VvzxSCrErxMBl6s14u2cd5c3r/fiGnaR3u8nxA+GpUPDjD6lNh5\n" +
            "or6BubNGS4NQMrMQ2OL31d5P3qcPZtQoJNdz1MAj5y4qOQBKA384VdIDDF8gJl4k\n" +
            "j5zYqI0tn06/UKWyN3aBknXBKY//LwFBbksSdAeLeHClnbfxpz0hTlj31IT8Td9U\n" +
            "MHgOFCXFKwkUDZH8pou/7Q4eYWwICCcaPp3QA0wv3FNwyBmgamw7quqbk7xiJuz7\n" +
            "1E/yfdAXEjlPRibVjvwpopYitZcGqIS0Mt9bXtwugzdeQh9TF2karA==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        this.privateKeyStringNonRsa =
            "-----BEGIN DSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,B07DB5293FAAC733\n" +
            "\n" +
            "G2Nsh3WOOIqtLqII3JKflwEM600WtPL1lTt1F98+7bkHh7+GYbZ412uTgFSjpTWQ\n" +
            "nj7yb4Zrq3hmDE/He0cwu+YPXMUwaBFxRUDDmIWL94z4VBguyqUjSMNaEHrZu+Vi\n" +
            "QUqWyPLoUeFWxAcK+iqxkT+595l1mGKnZQTFnjOSfDnZltMUdGhnRO2syOe17qqs\n" +
            "Pw2b6CTYxpOWRIvAtu701/0WMWWRfEkWWEXXggf37cCn4qPtuGZC9rD4iS60kkxy\n" +
            "nj8hHUa/vx/lerbUf0Do71JtYYoIeirbOwZXC58ME+S9KX96BkkzxbTQL1tavJUa\n" +
            "bEPgumwbjeVA+gVDFsS2saUgmTKbjFISvRr2x77eDZo7x6NKpQjq3eHn+rvzHnHg\n" +
            "tJE0qHOw1ffTOVCVJTBKOcWa1mEUJViJ4SQOdyjsjIP9LrIvISpA+1Bk62A/4tgY\n" +
            "meTHg/uxMaN8ksNmogdP7RZkDHaYQ5EkrSj8BfOxb3QQutyDaL4bQZ7E47cw9szN\n" +
            "YdXyR3a94AVNnYM49mzF2jO6x5YQtZAdaaQh7N7mcBOka6UA2BnfZxNU5RcE1Ge/\n" +
            "CM9VeSSkBwiVg99ipKe3v3YAWG09E+DHEsG/r8TkX6peTU7xRTRL2CuJIhgwfSV/\n" +
            "Z6Tq8Z0xi42WJVaKekcYQN4hjEFA6Ua7Gu7hNHwK7hdPCXdeQIOxR3kB6ZiFKswh\n" +
            "ovF7n1/iubX0o5b0DniMGMFjPW59r5e4FU3wI5dgP7ro5m0AwZ5JXVWcDNa+zyy/\n" +
            "3f7qgu4KKM1TysB/cUEHRYgeO1zVBie6mru0q8aJWE9UP2KzofL+B/ElcU4rZxNh\n" +
            "rGkEiCNSU+eI9wkX/yUlxT1ymEM678zlLA3kcBvJgyoTPFT/ajMdq59FeNqQ8o7x\n" +
            "cyXfQJ6aHFCuG3qB2iqUUOUmNgyzEvDo1d8QlR7bUs0vnum/qUN98c86ObOE3JMO\n" +
            "5zIxxmx6at41qcZcfkb8IYAO3TgovujaAxZ19P9Y/OxgnveXRrQR+uaBEL2ydr+S\n" +
            "XKiXC7R6zqNELvK2JqrsfKu1LlQ8Pd0L2w9rQav8eobx6mLZC4JdlgjYb7+L6/IF\n" +
            "8nAn3+JUFVmzryHEbJ6Kqcb6VmBzI771BAnJnzVemN2PJNIEbiMmzM9r7qEnMg2D\n" +
            "-----END DSA PRIVATE KEY-----";
        this.privateKeyStringNonRsaNoPassword =
            "-----BEGIN DSA PRIVATE KEY-----\n" +
            "MIIDVgIBAAKCAQEAwh+wZY0iayGjeIePlqHlDw4aPXSXrt14ZRFRkeCN47Rj/ZTY\n" +
            "/M75BZiuJuymxzulMKsrM8R84CUKH+tYJIwUetIPIzH/KBea9v4LOWzs4bG2HyJQ\n" +
            "ZWSamMYwL+hxa7MunFbFPNqacl3Uk8sub6gaiAvkjc83UeSGt7H8/OgMopS+IbzH\n" +
            "MPRE6pOR/d5iJIDNCnqlp8WD4/70z4RTJiME6XdzjM7qiesB25DN4+JtXzJfL3FN\n" +
            "yImgFTmUhKsfW69qJl/1mBQp6uVV3knR/BMbg5t4OtJNMp+onoCeEkE1H6KXCfkB\n" +
            "39404Rn4mvLqEaiOwG64Bjt01Of5lBmVV9EJ+QIhAJWdJx+2cWH0ZP/Gm13rENb3\n" +
            "RdZFJ/o1nRiZqmIs/6PXAoIBACkFMOe9d6AOWA14q7GrGYUHjSkP8p+/a32eAbvi\n" +
            "rdAOlSIgvRsmsyH+n4TAIeARRVvkWLYe1XC2mKAe/k0nUb4CBE46KTy4c+w+HeFJ\n" +
            "03in8YEDqiFOeV1jIzTIX/FwwwK8er8XeW9h3vxByHH5i6Mc0tleEHELBCxbhbwE\n" +
            "I8tGcpgJDOnw4S7RKE6J55hCu9W8cW7l113IfQ6GANp/yxgC2bPr+JDCxLDIFUFU\n" +
            "7iG0AFJ0WOJ2mlcZF0UZtbuuTEz38rq+GPfJBYXZGlwKW8vdtODDI4XSEDc8i/O4\n" +
            "idsk8DQi5j/i9azHWgphbZYW82AXf4M05NHWXV03HnnBE7UCggEAJ7awS055qn5w\n" +
            "JKHddJjZ20Vjwfcveatze7DtBejLJyFvABVSjJHbpc6mr71nBOaC6Oh3WeNkXCIK\n" +
            "XD3d6sgz+iY8euByOny7QLLfPP9i5ZtTVL8iCUWakTuAD8BEbMLSDT8FXUYN88Za\n" +
            "6pE1Gd2lr72nEU9vn9FQVZxAEBvTQP5WvMSDEeztSllXBjVb9tBi4wfA+pHB5/KG\n" +
            "yPWfIXJU3YuvDDxZHLDIr0FyzupVC4v2nsK0OylNePv45upLqHsKH5p/2Xq9hbAc\n" +
            "aX9Z2IrofMRVmABHUs1znHuPAQ3T+T2Ego8EJDCP/gFSfRkc4zriYQPd/kql3bZm\n" +
            "5EsPCPrIkQIhAICi7eNNexHlXQ37PBDgHtjPUE9aACPBfOS5lP+lWalT\n" +
            "-----END DSA PRIVATE KEY-----";
        this.publicKeyStringNonRsa =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQDCH7BljSJrIaN4h4+WoeUPDho9dJeu\n" +
            "3XhlEVGR4I3jtGP9lNj8zvkFmK4m7KbHO6UwqyszxHzgJQof61gkjBR60g8jMf8o\n" +
            "F5r2/gs5bOzhsbYfIlBlZJqYxjAv6HFrsy6cVsU82ppyXdSTyy5vqBqIC+SNzzdR\n" +
            "5Ia3sfz86AyilL4hvMcw9ETqk5H93mIkgM0KeqWnxYPj/vTPhFMmIwTpd3OMzuqJ\n" +
            "6wHbkM3j4m1fMl8vcU3IiaAVOZSEqx9br2omX/WYFCnq5VXeSdH8ExuDm3g60k0y\n" +
            "n6iegJ4SQTUfopcJ+QHf3jThGfia8uoRqI7AbrgGO3TU5/mUGZVX0Qn5AiEAlZ0n\n" +
            "H7ZxYfRk/8abXesQ1vdF1kUn+jWdGJmqYiz/o9cCggEAKQUw5713oA5YDXirsasZ\n" +
            "hQeNKQ/yn79rfZ4Bu+Kt0A6VIiC9GyazIf6fhMAh4BFFW+RYth7VcLaYoB7+TSdR\n" +
            "vgIETjopPLhz7D4d4UnTeKfxgQOqIU55XWMjNMhf8XDDArx6vxd5b2He/EHIcfmL\n" +
            "oxzS2V4QcQsELFuFvAQjy0ZymAkM6fDhLtEoTonnmEK71bxxbuXXXch9DoYA2n/L\n" +
            "GALZs+v4kMLEsMgVQVTuIbQAUnRY4naaVxkXRRm1u65MTPfyur4Y98kFhdkaXApb\n" +
            "y9204MMjhdIQNzyL87iJ2yTwNCLmP+L1rMdaCmFtlhbzYBd/gzTk0dZdXTceecET\n" +
            "tQOCAQUAAoIBACe2sEtOeap+cCSh3XSY2dtFY8H3L3mrc3uw7QXoyychbwAVUoyR\n" +
            "26XOpq+9ZwTmgujod1njZFwiClw93erIM/omPHrgcjp8u0Cy3zz/YuWbU1S/IglF\n" +
            "mpE7gA/ARGzC0g0/BV1GDfPGWuqRNRndpa+9pxFPb5/RUFWcQBAb00D+VrzEgxHs\n" +
            "7UpZVwY1W/bQYuMHwPqRwefyhsj1nyFyVN2Lrww8WRywyK9Bcs7qVQuL9p7CtDsp\n" +
            "TXj7+ObqS6h7Ch+af9l6vYWwHGl/WdiK6HzEVZgAR1LNc5x7jwEN0/k9hIKPBCQw\n" +
            "j/4BUn0ZHOM64mED3f5Kpd22ZuRLDwj6yJE=\n" +
            "-----END PUBLIC KEY-----";
    }

    @Test
    public void testConstructor()
    {
        Assert.assertSame(this.factory.pemParserFactory(), this.pemParserFactory);
        Assert.assertSame(this.factory.bcKeyParametersFactory(), this.bcPublicKeyParametersFactory);
        Assert.assertSame(this.factory.pemDecryptorProviderBuilder(), this.pemDecryptorProviderBuilder);
        Assert.assertSame(this.factory.pkcs8DecryptorProviderBuilder(), this.pkcs8DecryptorProviderBuilder);
        Assert.assertSame(this.factory.keyGenerator(), this.keyGenerator);
        Assert.assertSame(this.factory.random(), this.random);
    }

    @Test
    public void testConstructorDefaults()
    {
        this.factory = new KeyFactory();

        Assert.assertSame(this.factory.pemParserFactory().getClass(), PemParserFactory.class);
        Assert.assertSame(this.factory.bcKeyParametersFactory().getClass(), BcKeyParametersFactory.class);
        Assert.assertSame(this.factory.pemDecryptorProviderBuilder().getClass(), JcePEMDecryptorProviderBuilder.class);
        Assert.assertSame(
            this.factory.pkcs8DecryptorProviderBuilder().getClass(),
            JceOpenSSLPKCS8DecryptorProviderBuilder.class
        );
        Assert.assertSame(this.factory.keyGenerator().getClass(), RSAKeyPairGenerator.class);
        Assert.assertSame(this.factory.random().getClass(), SecureRandom.class);
    }

    @Test
    public void testGeneratePrivateKey()
    {
        PrivateKey privateKey = this.factory.generatePrivateKey();

        Assert.assertEquals(privateKey.publicExponent(), BigInteger.valueOf(65537));
        Assert.assertEquals(privateKey.size(), 2048);
    }

    @Test
    public void testGeneratePrivateKeyWithSize()
    {
        PrivateKey privateKey = this.factory.generatePrivateKey(4096);

        Assert.assertEquals(privateKey.publicExponent(), BigInteger.valueOf(65537));
        Assert.assertEquals(privateKey.size(), 4096);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGeneratePrivateKeyFailure()
    {
        AsymmetricCipherKeyPairGenerator mockKeyGenerator = Mockito.mock(AsymmetricCipherKeyPairGenerator.class);
        Mockito.when(mockKeyGenerator.generateKeyPair()).thenReturn(new AsymmetricCipherKeyPair(null, null));
        this.factory = new KeyFactory(
            this.pemParserFactory,
            this.bcPublicKeyParametersFactory,
            this.pemDecryptorProviderBuilder,
            this.pkcs8DecryptorProviderBuilder,
            mockKeyGenerator,
            this.random
        );

        this.factory.generatePrivateKey();
    }

    @Test
    public void testCreatePrivateKeyWithPassword() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(
            this.stringToInputStream(this.privateKeyString),
            "password"
        );

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePrivateKeyWithPasswordByteArray() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(
            this.privateKeyString.getBytes(Charset.forName("US-ASCII")),
            "password"
        );

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePrivateKeyWithPasswordString() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(this.privateKeyString, "password");

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePrivateKeyWithPasswordPkcs8() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(this.privateKeyStringPkcs8, "password");

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePrivateKeyWithPasswordFile() throws Throwable
    {
        File input = new File(this.getClass().getClassLoader().getResource("pem/rsa-2048.private.pem").toURI());
        PrivateKey privateKey = this.factory.createPrivateKey(input, "password");

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePrivateKeyNoPassword() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(
            this.stringToInputStream(this.privateKeyStringNoPassword)
        );

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyStringNoPassword);
    }

    @Test
    public void testCreatePrivateKeyNoPasswordByteArray() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(
            this.privateKeyStringNoPassword.getBytes(Charset.forName("US-ASCII"))
        );

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyStringNoPassword);
    }

    @Test
    public void testCreatePrivateKeyNoPasswordString() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(this.privateKeyStringNoPassword);

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyStringNoPassword);
    }

    @Test
    public void testCreatePrivateKeyNoPasswordPkcs8() throws Throwable
    {
        PrivateKey privateKey = this.factory.createPrivateKey(this.privateKeyStringPkcs8NoPassword);

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyStringNoPassword);
    }

    @Test
    public void testCreatePrivateKeyNoPasswordFile() throws Throwable
    {
        File input = new File(this.getClass().getClassLoader().getResource("pem/rsa-2048-nopass.private.pem").toURI());
        PrivateKey privateKey = this.factory.createPrivateKey(input);

        Assert.assertEquals(privateKey.publicKey().toString(), this.publicKeyStringNoPassword);
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyFailureNonPemData() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(""), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyNoPasswordFailureNonPemData() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(""));
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureNoPemEnd() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream("-----BEGIN RSA PRIVATE KEY-----\n"), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyNoPasswordFailureNoPemEnd() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream("-----BEGIN RSA PRIVATE KEY-----\n"));
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureNotPrivateKey() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.publicKeyString), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyNoPasswordFailureNotPrivateKey() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.publicKeyString));
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureKeyParameterConversion() throws Throwable
    {
        BcKeyParametersFactory mockKeyParametersFactory = Mockito.mock(BcKeyParametersFactory.class);
        Mockito.when(mockKeyParametersFactory.createPrivateKeyParameters(Mockito.any(PrivateKeyInfo.class)))
            .thenThrow(new IOException());
        this.factory = new KeyFactory(
            this.pemParserFactory,
            mockKeyParametersFactory,
            this.pemDecryptorProviderBuilder,
            this.pkcs8DecryptorProviderBuilder,
            this.keyGenerator,
            this.random
        );

        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyString), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyNoPasswordFailureKeyParameterConversion() throws Throwable
    {
        BcKeyParametersFactory mockKeyParametersFactory = Mockito.mock(BcKeyParametersFactory.class);
        Mockito.when(mockKeyParametersFactory.createPrivateKeyParameters(Mockito.any(PrivateKeyInfo.class)))
            .thenThrow(new IOException());
        this.factory = new KeyFactory(
            this.pemParserFactory,
            mockKeyParametersFactory,
            this.pemDecryptorProviderBuilder,
            this.pkcs8DecryptorProviderBuilder,
            this.keyGenerator,
            this.random
        );

        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyStringNoPassword));
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureNotRsaKey() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyStringNonRsa), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyNoPasswordFailureNotRsaKey() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyStringNonRsaNoPassword));
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureWrongPassword() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyString), "foobar");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureWrongPasswordPkcs8() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyStringPkcs8), "foobar");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureKeyPkcs8OperatorCreation() throws Throwable
    {
        JceOpenSSLPKCS8DecryptorProviderBuilder mockPkcs8DecryptorProviderBuilder =
            Mockito.mock(JceOpenSSLPKCS8DecryptorProviderBuilder.class);
        Mockito.when(mockPkcs8DecryptorProviderBuilder.build("password".toCharArray()))
            .thenThrow(new OperatorCreationException(""));
        this.factory = new KeyFactory(
            this.pemParserFactory,
            this.bcPublicKeyParametersFactory,
            this.pemDecryptorProviderBuilder,
            mockPkcs8DecryptorProviderBuilder,
            this.keyGenerator,
            this.random
        );

        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyStringPkcs8), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureDecryption() throws Throwable
    {
        this.factory.createPrivateKey(this.stringToInputStream(this.privateKeyStringWrongIv), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyWithPasswordFailureFileNotFound() throws Throwable
    {
        this.factory.createPrivateKey(new File("nonexistent"), "password");
    }

    @Test(expectedExceptions = PrivateKeyReadException.class)
    public void testCreatePrivateKeyNoPasswordFailureFileNotFound() throws Throwable
    {
        this.factory.createPrivateKey(new File("nonexistent"));
    }

    @Test
    public void testCreatePublicKey() throws Throwable
    {
        PublicKey publicKey = this.factory.createPublicKey(this.stringToInputStream(this.publicKeyString));

        Assert.assertEquals(publicKey.toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePublicKeyByteArray() throws Throwable
    {
        PublicKey publicKey = this.factory.createPublicKey(this.publicKeyString.getBytes(Charset.forName("US-ASCII")));

        Assert.assertEquals(publicKey.toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePublicKeyString() throws Throwable
    {
        PublicKey publicKey = this.factory.createPublicKey(this.publicKeyString);

        Assert.assertEquals(publicKey.toString(), this.publicKeyString);
    }

    @Test
    public void testCreatePublicKeyStringFile() throws Throwable
    {
        File input = new File(this.getClass().getClassLoader().getResource("pem/rsa-2048.public.pem").toURI());
        PublicKey publicKey = this.factory.createPublicKey(input);

        Assert.assertEquals(publicKey.toString(), this.publicKeyString);
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNonPemData() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream(""));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNoPemEnd() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream("-----BEGIN PUBLIC KEY-----\n"));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNotPublicKey() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream(this.privateKeyStringNoPassword));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureKeyParameterConversion() throws Throwable
    {
        BcKeyParametersFactory mockKeyParametersFactory = Mockito.mock(BcKeyParametersFactory.class);
        Mockito.when(mockKeyParametersFactory.createPublicKeyParameters(Mockito.any(SubjectPublicKeyInfo.class)))
            .thenThrow(new IOException());
        this.factory = new KeyFactory(
            this.pemParserFactory,
            mockKeyParametersFactory,
            this.pemDecryptorProviderBuilder,
            this.pkcs8DecryptorProviderBuilder,
            this.keyGenerator,
            this.random
        );

        this.factory.createPublicKey(this.stringToInputStream(this.publicKeyString));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureNotRsaKey() throws Throwable
    {
        this.factory.createPublicKey(this.stringToInputStream(this.publicKeyStringNonRsa));
    }

    @Test(expectedExceptions = PublicKeyReadException.class)
    public void testCreatePublicKeyFailureFileNotFound() throws Throwable
    {
        this.factory.createPublicKey(new File("nonexistent"));
    }

    @Test
    public void testCloseInputStreamFailure() throws Throwable
    {
        InputStream input = Mockito.mock(InputStream.class);
        Mockito.doThrow(new IOException()).when(input).close();
        Method closeInputStream = KeyFactory.class.getDeclaredMethod("closeInputStream", InputStream.class);

        try {
            closeInputStream.invoke(this.factory, input);
            Assert.fail();
        } catch (InvocationTargetException e) {
            Assert.assertNotNull(e.getCause());
            Assert.assertSame(e.getCause().getClass(), RuntimeException.class);
            Assert.assertEquals(e.getCause().getMessage(), "Unable to close stream.");
        }
    }

    protected InputStream stringToInputStream(String string)
    {
        return new ByteArrayInputStream(string.getBytes(Charset.forName("US-ASCII")));
    }

    private KeyFactory factory;
    private PemParserFactory pemParserFactory;
    private BcKeyParametersFactory bcPublicKeyParametersFactory;
    private JcePEMDecryptorProviderBuilder pemDecryptorProviderBuilder;
    private JceOpenSSLPKCS8DecryptorProviderBuilder pkcs8DecryptorProviderBuilder;
    private JcaPEMKeyConverter keyConverter;
    private RSAKeyPairGenerator keyGenerator;
    private SecureRandom random;
    private String privateKeyString;
    private String publicKeyString;
    private String privateKeyStringNoPassword;
    private String publicKeyStringNoPassword;
    private String privateKeyStringPkcs8;
    private String privateKeyStringPkcs8NoPassword;
    private String privateKeyStringWrongIv;
    private String privateKeyStringNonRsa;
    private String privateKeyStringNonRsaNoPassword;
    private String publicKeyStringNonRsa;
}
