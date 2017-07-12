// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_multipath_client.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base/run_loop.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_data_reader.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/tools/quic/platform/impl/quic_socket_utils.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

// TODO(rtenneti): Add support for MMSG_MORE.
#define MMSG_MORE 0
using std::string;

namespace net {

const int kEpollFlags = EPOLLIN | EPOLLOUT | EPOLLET;

QuicMultipathClient::QuicMultipathClient(QuicSocketAddress server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       EpollServer* epoll_server,
                       std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicMultipathClient(server_address,
                 server_id,
                 supported_versions,
                 QuicConfig(),
                 epoll_server,
                 std::move(proof_verifier)) {}

QuicMultipathClient::QuicMultipathClient(QuicSocketAddress server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       const QuicConfig& config,
                       EpollServer* epoll_server,
                       std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClientBase(
          server_id,
          supported_versions,
          config,
          new QuicEpollConnectionHelper(epoll_server, QuicAllocator::SIMPLE),
          new QuicEpollAlarmFactory(epoll_server),
          std::move(proof_verifier)),
      epoll_server_(epoll_server),
      packets_dropped_(0),
      overflow_supported_(false),
      packet_reader_(new QuicPacketReader()) {
  set_server_address(server_address);
}

QuicMultipathClient::~QuicMultipathClient() {
  session()->connection_manager()->PrintDebuggingInformation();
  if (connected()) {
    session()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client being torn down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }

  CleanUpAllUDPSockets();
}

void QuicMultipathClient::UseSubflowId(QuicSubflowId subflowId) {
  session()->connection_manager()->set_current_subflow_id(subflowId);
}

void QuicMultipathClient::AddSubflow() {
  // open socket
  int fd, port;
  CreateUDPSocketWithRandomPortAndConnectTo(server_address(),GetLatestClientAddress().host(),&fd,&port);

  // add socket to client
  QuicSubflowDescriptor d(QuicSocketAddress(GetLatestClientAddress().host(),port),server_address());
  fd_to_subflow_map_[fd] = d;
  fd_to_writer_map_[fd] = CreateWriter(fd);

  // add subflow
  session()->connection_manager()->AddPacketWriter(d,fd_to_writer_map_[fd].get());
  session()->connection_manager()->TryAddingSubflow(d);

  // register fd
  epoll_server_->RegisterFD(fd, this, kEpollFlags);
}

bool QuicMultipathClient::CreateUDPSocketWithRandomPortAndConnectTo(const QuicSocketAddress& serverAddress, const QuicIpAddress& localIpAddress, int *fd, int *port) {
  // Create socket
  *fd = QuicSocketUtils::CreateUDPSocket(serverAddress, &overflow_supported_);
  if (*fd < 0) {
    QUIC_LOG(ERROR) << "CreateSocket() failed: " << strerror(errno);
    return false;
  }

  // Bind to random port
  QuicSocketAddress localAddress(localIpAddress,0);
  sockaddr_storage localAddr = localAddress.generic_address();
  int rc = bind(*fd, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr));
  if (rc < 0) {
    QUIC_LOG(ERROR) << "Bind failed: " << strerror(errno);
    return false;
  }

  // Read out port
  QuicSocketAddress realLocalAddress;
  if (realLocalAddress.FromSocket(*fd) != 0) {
    QUIC_LOG(ERROR) << "Unable to get self address.  Error: "
                    << strerror(errno);
    return false;
  }
  *port = realLocalAddress.port();

  return true;
}

bool QuicMultipathClient::CreateUDPSocketAndBind(QuicSocketAddress server_address,
                                        QuicIpAddress bind_to_address,
                                        int bind_to_port) {
  epoll_server_->set_timeout_in_us(50 * 1000);

  int fd =
      QuicSocketUtils::CreateUDPSocket(server_address, &overflow_supported_);
  if (fd < 0) {
    return false;
  }

  QuicSocketAddress client_address;
  if (bind_to_address.IsInitialized()) {
    client_address = QuicSocketAddress(bind_to_address, local_port());
  } else if (server_address.host().address_family() == IpAddressFamily::IP_V4) {
    client_address = QuicSocketAddress(QuicIpAddress::Loopback4(), bind_to_port);
  } else {
    client_address = QuicSocketAddress(QuicIpAddress::Loopback6(), bind_to_port);
  }

  sockaddr_storage addr = client_address.generic_address();
  int rc = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (rc < 0) {
    QUIC_LOG(ERROR) << "Bind failed: " << strerror(errno);
    return false;
  }

  if (client_address.FromSocket(fd) != 0) {
    QUIC_LOG(ERROR) << "Unable to get self address.  Error: "
                    << strerror(errno);
  }

  fd_to_subflow_map_[fd] = QuicSubflowDescriptor(client_address,server_address);
  fd_to_writer_map_[fd] = CreateWriter(fd);
  latest_fd_ = fd;
  latest_client_address_ = client_address;

  epoll_server_->RegisterFD(fd, this, kEpollFlags);
  return true;
}

void QuicMultipathClient::CleanUpUDPSocket(int fd) {
  CleanUpUDPSocketImpl(fd);
  fd_to_subflow_map_.erase(fd);
}

void QuicMultipathClient::CleanUpAllUDPSockets() {
  for (std::pair<int, QuicSubflowDescriptor> fd_address : fd_to_subflow_map_) {
    CleanUpUDPSocketImpl(fd_address.first);
  }
  fd_to_subflow_map_.clear();
}

void QuicMultipathClient::CleanUpUDPSocketImpl(int fd) {
  if (fd > -1) {
    epoll_server_->UnregisterFD(fd);
    int rc = close(fd);
    DCHECK_EQ(0, rc);
  }
}

void QuicMultipathClient::RunEventLoop() {
  base::RunLoop().RunUntilIdle();
  epoll_server_->WaitForEventsAndExecuteCallbacks();
}

void QuicMultipathClient::OnEvent(int fd, EpollEvent* event) {
  //DCHECK_EQ(fd, GetLatestFD());

  if (event->in_events & EPOLLIN) {
    QUIC_LOG(INFO) << "EPOLLIN";
    bool more_to_read = true;
    while (connected() && more_to_read) {
      more_to_read = packet_reader_->ReadAndDispatchPackets(
          fd, fd_to_subflow_map_[fd].Self().port(),
          *helper()->GetClock(), this,
          overflow_supported_ ? &packets_dropped_ : nullptr);
    }
  }
  if (connected() && (event->in_events & EPOLLOUT)) {
    QUIC_LOG(INFO) << "EPOLLOUT";
    fd_to_writer_map_[fd]->SetWritable();
    session()->OnCanWrite(session()->connection_manager()->ConnectionOfSubflow(fd_to_subflow_map_[fd]));
    //session()->OnCanWrite(fd_to_subflow_map_[fd]);

    //writer()->SetWritable();
    //session()->connection()->OnCanWrite();
  }
  if (event->in_events & EPOLLERR) {
    QUIC_DLOG(INFO) << "Epollerr";
  }
}

std::unique_ptr<QuicDefaultPacketWriter> QuicMultipathClient::CreateWriter(int fd) {
  return std::unique_ptr<QuicDefaultPacketWriter>(new QuicDefaultPacketWriter(fd));
}

QuicPacketWriter* QuicMultipathClient::CreateQuicPacketWriter() {
  QuicDefaultPacketWriter *writer = fd_to_writer_map_[latest_fd_].get();
  return writer;
}

QuicSocketAddress QuicMultipathClient::GetLatestClientAddress() const {
  return latest_client_address_;
}

void QuicMultipathClient::ProcessPacket(const QuicSocketAddress& self_address,
                               const QuicSocketAddress& peer_address,
                               const QuicReceivedPacket& packet) {
  session()->ProcessUdpPacket(self_address, peer_address, packet);
}

}  // namespace net
