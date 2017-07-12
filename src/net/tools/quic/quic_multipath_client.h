// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy client, which connects to a specified port and sends QUIC
// request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUIC_MULTIPATH_CLIENT_H_
#define NET_TOOLS_QUIC_QUIC_MULTIPATH_CLIENT_H_

#include <cstdint>
#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "net/quic/core/quic_client_push_promise_index.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_spdy_stream.h"
#include "net/quic/platform/api/quic_containers.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_client_base.h"
#include "net/tools/quic/quic_client_session.h"
#include "net/tools/quic/quic_packet_reader.h"
#include "net/tools/quic/quic_process_packet_interface.h"
#include "net/tools/quic/quic_default_packet_writer.h"

namespace net {

class QuicServerId;

namespace test {
class QuicClientPeer;
}  // namespace test

class QuicMultipathClient : public QuicClientBase,
                   public EpollCallbackInterface,
                   public ProcessPacketInterface {
 public:
  // Create a quic client, which will have events managed by an externally owned
  // EpollServer.
  QuicMultipathClient(QuicSocketAddress server_address,
             const QuicServerId& server_id,
             const QuicVersionVector& supported_versions,
             EpollServer* epoll_server,
             std::unique_ptr<ProofVerifier> proof_verifier);
  QuicMultipathClient(QuicSocketAddress server_address,
             const QuicServerId& server_id,
             const QuicVersionVector& supported_versions,
             const QuicConfig& config,
             EpollServer* epoll_server,
             std::unique_ptr<ProofVerifier> proof_verifier);

  ~QuicMultipathClient() override;

  void UseSubflowId(QuicSubflowId subflowId);

  void AddSubflow();
  bool CreateUDPSocketWithRandomPortAndConnectTo(
      const QuicSocketAddress& serverAddress,
      const QuicIpAddress& localIpAddress,
      int *fd,
      int *port);

  // From EpollCallbackInterface
  void OnRegistration(EpollServer* eps, int fd, int event_mask) override {}
  void OnModification(int fd, int event_mask) override {}
  void OnEvent(int fd, EpollEvent* event) override;
  // |fd_| can be unregistered without the client being disconnected. This
  // happens in b3m QuicProber where we unregister |fd_| to feed in events to
  // the client from the SelectServer.
  void OnUnregistration(int fd, bool replaced) override {}
  void OnShutdown(EpollServer* eps, int fd) override {}

  // If the client has at least one UDP socket, return the latest created one.
  // Otherwise, return -1.
  //int GetLatestFD() const;

  // From QuicClientBase
  QuicSocketAddress GetLatestClientAddress() const override;

  // Implements ProcessPacketInterface. This will be called for each received
  // packet.
  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

 protected:
  std::unique_ptr<QuicDefaultPacketWriter> CreateWriter(int fd);

  // From QuicClientBase
  QuicPacketWriter* CreateQuicPacketWriter() override;
  void RunEventLoop() override;
  bool CreateUDPSocketAndBind(QuicSocketAddress server_address,
                              QuicIpAddress bind_to_address,
                              int bind_to_port) override;
  void CleanUpAllUDPSockets() override;

  // If |fd| is an open UDP socket, unregister and close it. Otherwise, do
  // nothing.
  virtual void CleanUpUDPSocket(int fd);

  EpollServer* epoll_server() { return epoll_server_; }

 private:
  friend class test::QuicClientPeer;

  // Actually clean up |fd|.
  void CleanUpUDPSocketImpl(int fd);

  // Listens for events on the client socket.
  EpollServer* epoll_server_;

  // If overflow_supported_ is true, this will be the number of packets dropped
  // during the lifetime of the server.
  QuicPacketCount packets_dropped_;

  // True if the kernel supports SO_RXQ_OVFL, the number of packets dropped
  // because the socket would otherwise overflow.
  bool overflow_supported_;

  // Point to a QuicPacketReader object on the heap. The reader allocates more
  // space than allowed on the stack.
  std::unique_ptr<QuicPacketReader> packet_reader_;

  std::map<int, QuicSubflowDescriptor> fd_to_subflow_map_;
  std::map<int, std::unique_ptr<QuicDefaultPacketWriter> > fd_to_writer_map_;
  int latest_fd_;
  QuicSocketAddress latest_client_address_;

  DISALLOW_COPY_AND_ASSIGN(QuicMultipathClient);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_MULTIPATH_CLIENT_H_
