/*
 * This file is part of the Lockbox package.
 *
 * Copyright © 2013 Erin Millard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package co.lqnt.lockbox.util.codec;

import co.lqnt.lockbox.util.codec.exception.DecodingFailedException;
import java.nio.charset.Charset;
import javax.xml.bind.DatatypeConverter;

/**
 * Codec for Base64 URI-safe variant.
 *
 * See <a href="http://tools.ietf.org/html/rfc4648#section-5">RFC 4648 section 5</a>.
 */
public class Base64UriCodec implements CodecInterface
{
    /**
     * Encode the supplied data packet.
     *
     * @param data The data to encode.
     *
     * @return The encoded data.
     */
    public byte[] encode(final byte[] data)
    {
        return DatatypeConverter.printBase64Binary(data)
            .replace('+', '-')
            .replace('/', '_')
            .replace("=", "")
            .getBytes(Charset.forName("US-ASCII"));
    }

    /**
     * Encode the supplied data packet.
     *
     * @param data The data to encode.
     *
     * @return The encoded data.
     */
    public byte[] encode(final String data)
    {
        return this.encode(data.getBytes(Charset.forName("US-ASCII")));
    }

    /**
     * Decode the supplied data packet.
     *
     * @param data The data to decode.
     *
     * @return The decoded data.
     * @throws DecodingFailedException If the decoding fails.
     */
    public byte[] decode(final byte[] data) throws DecodingFailedException
    {
        return this.decode(new String(data, Charset.forName("US-ASCII")));
    }

    /**
     * Decode the supplied data packet.
     *
     * @param data The data to decode.
     *
     * @return The decoded data.
     * @throws DecodingFailedException If the decoding fails.
     */
    public byte[] decode(final String data) throws DecodingFailedException
    {
        if (!data.matches("^[A-Za-z0-9_-]*$")) {
            throw new DecodingFailedException();
        }

        StringBuilder transformedData = new StringBuilder(
            data.replace('-', '+').replace('_', '/')
        );

        int remainder = transformedData.length() % 4;
        if (0 != remainder) {
            for (int i = 0; i < 4 - remainder; ++i) {
                transformedData.append('=');
            }
        }

        return DatatypeConverter.parseBase64Binary(transformedData.toString());
    }
}
