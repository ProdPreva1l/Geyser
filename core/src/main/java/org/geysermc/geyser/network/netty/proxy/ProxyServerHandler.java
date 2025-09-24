/*
 * Copyright (c) 2019-2023 GeyserMC. http://geysermc.org
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
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.haproxy.HAProxyCommand;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.handler.codec.haproxy.HAProxyProtocolException;
import io.netty.handler.codec.haproxy.HAProxyProtocolVersion;
import io.netty.handler.codec.haproxy.HAProxyProxiedProtocol;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.cloudburstmc.protocol.bedrock.BedrockPeer;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.network.GeyserBedrockPeer;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

@ChannelHandler.Sharable
public class ProxyServerHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    private static final InternalLogger log = InternalLoggerFactory.getInstance(ProxyServerHandler.class);
    public static final String NAME = "rak-proxy-server-handler";

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
        assert GeyserImpl.getInstance().getGeyserServer().getProxiedAddresses() != null;
        log.debug("attempting to verify haproxy header for " + packet.sender());
        ByteBuf content = packet.content();
        GeyserBedrockPeer peer = (GeyserBedrockPeer) ctx.pipeline().get(BedrockPeer.NAME);
        InetSocketAddress presentAddress = GeyserImpl.getInstance().getGeyserServer().getProxiedAddresses().get(packet.sender());

        if (peer != null && presentAddress == null) {
            log.debug("(1) we didnt receive a valid haproxy header so we ignore packets from " + packet.sender());
            return; // we didnt receive a valid haproxy header so we ignore packets
        }

        if (presentAddress != null) {
            ctx.fireChannelRead(packet.retain());
            return;
        }

        final HAProxyMessage decoded;
        try {
            if ((decoded = decodeProxyV2Header(content, packet)) == null) {
                log.debug("(2) we didnt receive a valid haproxy header so we ignore packets from " + packet.sender());
                return; // proxy protocol v2 header was not present in the packet, ignore connection.
            }
        } catch (HAProxyProtocolException e) {
            log.debug("{} sent malformed proxy protocol v2 header", packet.sender(), e);
            return;
        }

        presentAddress = new InetSocketAddress(decoded.sourceAddress(), decoded.sourcePort());
        log.debug("Got proxy protocol v2 header: (from {}) {}", packet.sender(), presentAddress);

        GeyserImpl.getInstance().getGeyserServer().getProxiedAddresses().put(packet.sender(), presentAddress);

        ctx.fireChannelRead(packet.retain());
    }

    public static HAProxyMessage decodeProxyV2Header(ByteBuf buffer, DatagramPacket packet) {
        if (buffer.readableBytes() < 16) {
            log.debug("invalid header size for " + packet.sender());
            return null;
        }

        int startIndex = buffer.readerIndex();

        // Read and verify signature (12 bytes)
        byte[] expectedSignature = {13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10};
        byte[] signature = new byte[12];
        buffer.readBytes(signature);

        for (int i = 0; i < 12; i++) {
            if (signature[i] != expectedSignature[i]) {
                buffer.readerIndex(startIndex);
                log.debug("invalid haproxy signature '{}' for {}", signature, packet.sender());
                return null;
            }
        }

        // Read version and command (1 byte)
        byte versionCommand = buffer.readByte();
        if (versionCommand != 33) { // Version 2 (bits 7-4 = 0010) + PROXY command (bits 3-0 = 0001)
            buffer.readerIndex(startIndex);
            log.debug("invalid version & command '{}' for {}", versionCommand, packet.sender());
            return null;
        }

        // Read protocol and family (1 byte)
        byte protocolFamily = buffer.readByte();

        // Read length (2 bytes)
        int length = buffer.readUnsignedShort();

        if (buffer.readableBytes() < length) {
            buffer.readerIndex(startIndex);
            log.debug("invalid header size for " + packet.sender());
            return null;
        }

        try {
            HAProxyProxiedProtocol proxiedProtocol;
            String srcIP;
            String destIP;
            int srcPort;
            int destPort;

            if (protocolFamily == 18) { // IPv4 + UDP
                if (length != 12) {
                    buffer.readerIndex(startIndex);
                    log.debug("invalid header size for " + packet.sender());
                    return null;
                }

                proxiedProtocol = HAProxyProxiedProtocol.UDP4;

                // Read source IPv4 address (4 bytes)
                byte[] srcIpBytes = new byte[4];
                buffer.readBytes(srcIpBytes);
                InetAddress srcIpAddr = InetAddress.getByAddress(srcIpBytes);
                srcIP = srcIpAddr.getHostAddress();

                // Read destination IPv4 address (4 bytes)
                byte[] destIpBytes = new byte[4];
                buffer.readBytes(destIpBytes);
                InetAddress destIpAddr = InetAddress.getByAddress(destIpBytes);
                destIP = destIpAddr.getHostAddress();

                // Read source port (2 bytes)
                srcPort = buffer.readUnsignedShort();

                // Read destination port (2 bytes)
                destPort = buffer.readUnsignedShort();

            } else if (protocolFamily == 34) { // IPv6 + UDP
                if (length != 36) {
                    buffer.readerIndex(startIndex);
                    log.debug("invalid header size for " + packet.sender());
                    return null;
                }

                proxiedProtocol = HAProxyProxiedProtocol.UDP6;

                // Read source IPv6 address (16 bytes)
                byte[] srcIpBytes = new byte[16];
                buffer.readBytes(srcIpBytes);
                InetAddress srcIpAddr = InetAddress.getByAddress(srcIpBytes);
                srcIP = srcIpAddr.getHostAddress();

                // Read destination IPv6 address (16 bytes)
                byte[] destIpBytes = new byte[16];
                buffer.readBytes(destIpBytes);
                InetAddress destIpAddr = InetAddress.getByAddress(destIpBytes);
                destIP = destIpAddr.getHostAddress();

                // Read source port (2 bytes)
                srcPort = buffer.readUnsignedShort();

                // Read destination port (2 bytes)
                destPort = buffer.readUnsignedShort();

            } else {
                // Only UDP protocols are supported, reject everything else
                buffer.readerIndex(startIndex);
                log.debug("invalid header protocol for " + packet.sender());
                return null;
            }

            return new HAProxyMessage(
                HAProxyProtocolVersion.V2,
                HAProxyCommand.PROXY,
                proxiedProtocol,
                srcIP,
                destIP,
                srcPort,
                destPort
            );

        } catch (UnknownHostException e) {
            buffer.readerIndex(startIndex);
            return null;
        }
    }
}
