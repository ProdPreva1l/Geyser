/*
 * Copyright (c) 2025 GeyserMC. http://geysermc.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author GeyserMC
 * @link https://github.com/GeyserMC/Geyser
 */

package org.geysermc.geyser.network.netty.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.ProtocolDetectionResult;
import io.netty.handler.codec.ProtocolDetectionState;
import io.netty.handler.codec.haproxy.HAProxyCommand;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import io.netty.handler.codec.haproxy.HAProxyProtocolException;
import io.netty.handler.codec.haproxy.HAProxyProtocolVersion;
import io.netty.handler.codec.haproxy.HAProxyProxiedProtocol;
import io.netty.handler.codec.haproxy.HAProxySSLTLV;
import io.netty.handler.codec.haproxy.HAProxyTLV;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.cloudburstmc.protocol.bedrock.BedrockPeer;
import org.geysermc.geyser.network.GeyserBedrockPeer;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UDPProxyProtocolHandler extends ChannelInboundHandlerAdapter {
    private static final InternalLogger log = InternalLoggerFactory.getInstance(UDPProxyProtocolHandler.class);

    private HAProxyMessage proxyMessage = null;
    private boolean firstPacketProcessed = false;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof DatagramPacket packet && !firstPacketProcessed) {
            ByteBuf content = packet.content();
            
            // Check if this packet has PROXY protocol header
            ProtocolDetectionResult<HAProxyProtocolVersion> detection =
                HAProxyMessageDecoder.detectProtocol(content);
                
            if (detection.state() == ProtocolDetectionState.DETECTED) {
                try {
                    // Decode the PROXY header
                    proxyMessage = decodeHeader(content);
                    
                    log.info("PROXY Protocol detected!");
                    log.info("Real address: " + proxyMessage.sourceAddress());
                    log.info("Proxy address: " + proxyMessage.destinationAddress());
                    
                    // Store the address info somewhere accessible
                    GeyserBedrockPeer peer = (GeyserBedrockPeer) ctx.pipeline().get(BedrockPeer.NAME);
                    if (peer != null) {
                        peer.setRealAddress(new InetSocketAddress(proxyMessage.sourceAddress(), proxyMessage.sourcePort()));
                    }
                    
                    firstPacketProcessed = true;
                } catch (Exception e) {
                    log.error("Failed to decode PROXY protocol", e);
                }
            } else {
                // No PROXY header, treat as normal UDP
                firstPacketProcessed = true;
            }
        }
        
        // Continue with normal packet processing
        super.channelRead(ctx, msg);
    }

    /**
     * Decodes a version 2, binary proxy protocol header.
     *
     * @param header                     a version 2 proxy protocol header
     * @return                           {@link HAProxyMessage} instance
     * @throws HAProxyProtocolException  if any portion of the header is invalid
     */
    static HAProxyMessage decodeHeader(ByteBuf header) {
        ObjectUtil.checkNotNull(header, "header");

        if (header.readableBytes() < 16) {
            throw new HAProxyProtocolException(
                "incomplete header: " + header.readableBytes() + " bytes (expected: 16+ bytes)");
        }

        // Per spec, the 13th byte is the protocol version and command byte
        header.skipBytes(12);
        final byte verCmdByte = header.readByte();

        HAProxyProtocolVersion ver;
        try {
            ver = HAProxyProtocolVersion.valueOf(verCmdByte);
        } catch (IllegalArgumentException e) {
            throw new HAProxyProtocolException(e);
        }

        if (ver != HAProxyProtocolVersion.V2) {
            throw new HAProxyProtocolException("version 1 unsupported: 0x" + Integer.toHexString(verCmdByte));
        }

        HAProxyCommand cmd;
        try {
            cmd = HAProxyCommand.valueOf(verCmdByte);
        } catch (IllegalArgumentException e) {
            throw new HAProxyProtocolException(e);
        }

        if (cmd == HAProxyCommand.LOCAL) {
            return unknownMsg(HAProxyProtocolVersion.V2, HAProxyCommand.LOCAL);
        }

        // Per spec, the 14th byte is the protocol and address family byte
        HAProxyProxiedProtocol protAndFam;
        try {
            protAndFam = HAProxyProxiedProtocol.valueOf(header.readByte());
        } catch (IllegalArgumentException e) {
            throw new HAProxyProtocolException(e);
        }

        if (protAndFam == HAProxyProxiedProtocol.UNKNOWN) {
            return unknownMsg(HAProxyProtocolVersion.V2, HAProxyCommand.PROXY);
        }

        int addressInfoLen = header.readUnsignedShort();

        String srcAddress;
        String dstAddress;
        int addressLen;
        int srcPort = 0;
        int dstPort = 0;

        HAProxyProxiedProtocol.AddressFamily addressFamily = protAndFam.addressFamily();

        if (addressFamily == HAProxyProxiedProtocol.AddressFamily.AF_UNIX) {
            // unix sockets require 216 bytes for address information
            if (addressInfoLen < 216 || header.readableBytes() < 216) {
                throw new HAProxyProtocolException(
                    "incomplete UNIX socket address information: " +
                        Math.min(addressInfoLen, header.readableBytes()) + " bytes (expected: 216+ bytes)");
            }
            int startIdx = header.readerIndex();
            int addressEnd = header.indexOf(startIdx, startIdx + 108, (byte) 0); // FIND_NUL
            if (addressEnd == -1) {
                addressLen = 108;
            } else {
                addressLen = addressEnd - startIdx;
            }
            srcAddress = header.toString(startIdx, addressLen, CharsetUtil.US_ASCII);

            startIdx += 108;

            addressEnd = header.indexOf(startIdx, startIdx + 108, (byte) 0); // FIND_NUL
            if (addressEnd == -1) {
                addressLen = 108;
            } else {
                addressLen = addressEnd - startIdx;
            }
            dstAddress = header.toString(startIdx, addressLen, CharsetUtil.US_ASCII);
            // AF_UNIX defines that exactly 108 bytes are reserved for the address. The previous methods
            // did not increase the reader index although we already consumed the information.
            header.readerIndex(startIdx + 108);
        } else {
            if (addressFamily == HAProxyProxiedProtocol.AddressFamily.AF_IPv4) {
                // IPv4 requires 12 bytes for address information
                if (addressInfoLen < 12 || header.readableBytes() < 12) {
                    throw new HAProxyProtocolException(
                        "incomplete IPv4 address information: " +
                            Math.min(addressInfoLen, header.readableBytes()) + " bytes (expected: 12+ bytes)");
                }
                addressLen = 4;
            } else if (addressFamily == HAProxyProxiedProtocol.AddressFamily.AF_IPv6) {
                // IPv6 requires 36 bytes for address information
                if (addressInfoLen < 36 || header.readableBytes() < 36) {
                    throw new HAProxyProtocolException(
                        "incomplete IPv6 address information: " +
                            Math.min(addressInfoLen, header.readableBytes()) + " bytes (expected: 36+ bytes)");
                }
                addressLen = 16;
            } else {
                throw new HAProxyProtocolException(
                    "unable to parse address information (unknown address family: " + addressFamily + ')');
            }

            // Per spec, the src address begins at the 17th byte
            srcAddress = ipBytesToString(header, addressLen);
            dstAddress = ipBytesToString(header, addressLen);
            srcPort = header.readUnsignedShort();
            dstPort = header.readUnsignedShort();
        }

        final List<HAProxyTLV> tlvs = readTlvs(header);

        return new HAProxyMessage(ver, cmd, protAndFam, srcAddress, dstAddress, srcPort, dstPort, tlvs);
    }

    private static List<HAProxyTLV> readTlvs(final ByteBuf header) {
        HAProxyTLV haProxyTLV = readNextTLV(header, 0);
        if (haProxyTLV == null) {
            return Collections.emptyList();
        }
        // In most cases there are less than 4 TLVs available
        List<HAProxyTLV> haProxyTLVs = new ArrayList<HAProxyTLV>(4);

        do {
            haProxyTLVs.add(haProxyTLV);
            if (haProxyTLV instanceof HAProxySSLTLV) {
                haProxyTLVs.addAll(((HAProxySSLTLV) haProxyTLV).encapsulatedTLVs());
            }
        } while ((haProxyTLV = readNextTLV(header, 0)) != null);
        return haProxyTLVs;
    }

    private static HAProxyTLV readNextTLV(final ByteBuf header, int nestingLevel) {
        if (nestingLevel > 128) {
            throw new HAProxyProtocolException(
                "Maximum TLV nesting level reached: " + nestingLevel + " (expected: < " + 128 + ')');
        }
        // We need at least 4 bytes for a TLV
        if (header.readableBytes() < 4) {
            return null;
        }

        final byte typeAsByte = header.readByte();
        final HAProxyTLV.Type type = HAProxyTLV.Type.typeForByteValue(typeAsByte);

        final int length = header.readUnsignedShort();
        switch (type) {
            case PP2_TYPE_SSL:
                final ByteBuf rawContent = header.retainedSlice(header.readerIndex(), length);
                final ByteBuf byteBuf = header.readSlice(length);
                final byte client = byteBuf.readByte();
                final int verify = byteBuf.readInt();

                if (byteBuf.readableBytes() >= 4) {

                    final List<HAProxyTLV> encapsulatedTlvs = new ArrayList<HAProxyTLV>(4);
                    do {
                        final HAProxyTLV haProxyTLV = readNextTLV(byteBuf, nestingLevel + 1);
                        if (haProxyTLV == null) {
                            break;
                        }
                        encapsulatedTlvs.add(haProxyTLV);
                    } while (byteBuf.readableBytes() >= 4);

                    return new HAProxySSLTLV(verify, client, encapsulatedTlvs);
                }
                return new HAProxySSLTLV(verify, client, Collections.emptyList());
            // If we're not dealing with an SSL Type, we can use the same mechanism
            case PP2_TYPE_ALPN:
            case PP2_TYPE_AUTHORITY:
            case PP2_TYPE_SSL_VERSION:
            case PP2_TYPE_SSL_CN:
            case PP2_TYPE_NETNS:
            case OTHER:
                return new HAProxyTLV(type, header.readRetainedSlice(length));
            default:
                return null;
        }
    }

    /**
     * Convert ip address bytes to string representation
     *
     * @param header     buffer containing ip address bytes
     * @param addressLen number of bytes to read (4 bytes for IPv4, 16 bytes for IPv6)
     * @return           string representation of the ip address
     */
    private static String ipBytesToString(ByteBuf header, int addressLen) {
        StringBuilder sb = new StringBuilder();
        final int ipv4Len = 4;
        final int ipv6Len = 8;
        if (addressLen == ipv4Len) {
            for (int i = 0; i < ipv4Len; i++) {
                sb.append(header.readByte() & 0xff);
                sb.append('.');
            }
        } else {
            for (int i = 0; i < ipv6Len; i++) {
                sb.append(Integer.toHexString(header.readUnsignedShort()));
                sb.append(':');
            }
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    /**
     * Proxy protocol message for 'UNKNOWN' proxied protocols. Per spec, when the proxied protocol is
     * 'UNKNOWN' we must discard all other header values.
     */
    private static HAProxyMessage unknownMsg(HAProxyProtocolVersion version, HAProxyCommand command) {
        return new HAProxyMessage(version, command, HAProxyProxiedProtocol.UNKNOWN, null, null, 0, 0);
    }
}
