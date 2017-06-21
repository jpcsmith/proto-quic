// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_connection_manager.h"
#include <utility>

namespace net {

QuicConnectionManager::QuicConnectionManager(QuicConnection *connection)
    : connections_(std::map<QuicSubflowId, QuicConnection*>()),
      next_outgoing_subflow_id_(connection->perspective() == Perspective::IS_SERVER ? 2 : 3),
      packet_handler_(nullptr) {
  connections_.insert(
      std::pair<QuicSubflowId, QuicConnection*>(kInitialSubflowId,
          connection));
  connection->set_visitor(this);
}

QuicConnectionManager::~QuicConnectionManager() {
  // delete all connections but the first (first connection
  // is not owned by the connection manager)
  for(auto &it: connections_)
  {
    if(it.second != InitialConnection())
    {
      delete it.second;
    }
  }
  if(packet_handler_ != nullptr) {
    delete packet_handler_;
  }
}

void QuicConnectionManager::TryAddingSubflow(QuicSubflowDescriptor descriptor) {

  // Check if the initial connection already finished its handshake messages
  if(packet_handler_ == nullptr) {
    buffered_outgoing_subflow_attempts_.insert(descriptor);
    return;
  }

  OpenConnection(descriptor,GetNextOutgoingSubflowId(),SUBFLOW_OUTGOING);

  //TODO maybe send ping packet to open connection?
}

void QuicConnectionManager::CloseSubflow(QuicSubflowId id) {
  //TODO maybe similar to opening: Send subflow_close frames until one is acknowledged.
  CloseConnection(id);
}

void QuicConnectionManager::ProcessUdpPacket(const QuicSocketAddress& self_address,
                                   const QuicSocketAddress& peer_address,
                                   const QuicReceivedPacket& packet) {
  QuicSubflowDescriptor descriptor(self_address,peer_address);
  auto it = subflow_descriptor_map_.find(descriptor);

  // subflow already established
  if(it != subflow_descriptor_map_.end())
  {
    connections_[it->second]->ProcessUdpPacket(self_address,peer_address,packet);
  }
  else
  {
    if(packet_handler_ == nullptr) {
      // handshake not yet finished -> buffer request
      buffered_incoming_subflow_attempts_.push_back(
          std::pair<QuicSubflowDescriptor,std::unique_ptr<QuicReceivedPacket>>(
              QuicSubflowDescriptor(self_address,peer_address),packet.Clone()));
    } else {
      if(!packet_handler_->ProcessPacket(packet)) {
        //TODO error handling
        return;
      }
      else
      {
        //TODO check for validity of subflow id (not too big?)
        OpenConnection(
            QuicSubflowDescriptor(self_address,peer_address),
            packet_handler_->GetLastSubflowId(),
            SUBFLOW_INCOMING);
      }
    }
  }
}

void QuicConnectionManager::OpenConnection(QuicSubflowDescriptor descriptor, QuicSubflowId subflowId, SubflowDirection direction) {
  if(direction == SUBFLOW_OUTGOING) {
    if(subflowId % 2 != next_outgoing_subflow_id_ % 2) {
      //TODO error handling
    }
  } else {
    if(subflowId % 2 != (next_outgoing_subflow_id_+1) % 2) {
      //TODO error handling
    }
  }

  // Create new connection
  QuicConnection *connection = InitialConnection()->CloneToSubflow(
      descriptor.Peer(),
      CreatePacketWriter(),
      true);
  if(direction == SUBFLOW_OUTGOING) {
    connection->SendNewSubflowFrameInEveryPacket();
  }

  connections_.insert(
      std::pair<QuicSubflowId, QuicConnection*>(
          subflowId,
          connection));
  subflow_descriptor_map_.insert(
      std::pair<QuicSubflowDescriptor, QuicSubflowId>(
          descriptor,
          subflowId));
}

void QuicConnectionManager::CloseConnection(QuicSubflowId subflowId) {
  // remove connection
  connections_.erase(subflowId);

  // remove from subflow map
  QuicSubflowDescriptor descriptor;
  for(const auto& it: subflow_descriptor_map_) {
    if(it.second == subflowId)
    {
      descriptor = it.first;
      break;
    }
  }
  if(descriptor.IsInitialized())
  {
    subflow_descriptor_map_.erase(descriptor);
  }
}

QuicPacketWriter *QuicConnectionManager::CreatePacketWriter() {
  // E.g. Use QuicPerConnectionPacketWriter
  // Or take writer from first InitialConnection and share among connections
  return nullptr;
}

QuicSubflowId QuicConnectionManager::GetNextOutgoingSubflowId() {
  QuicSubflowId id = next_outgoing_subflow_id_;
  next_outgoing_subflow_id_ += 2;
  return id;
}

void QuicConnectionManager::OnStreamFrame(const QuicStreamFrame& frame) {
  if(visitor_ != nullptr) visitor_->OnStreamFrame(frame);
}
void QuicConnectionManager::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  if(visitor_ != nullptr) visitor_->OnWindowUpdateFrame(frame);
}
void QuicConnectionManager::OnBlockedFrame(const QuicBlockedFrame& frame) {
  if(visitor_ != nullptr) visitor_->OnBlockedFrame(frame);
}
void QuicConnectionManager::OnRstStream(const QuicRstStreamFrame& frame) {
  if(visitor_ != nullptr) visitor_->OnRstStream(frame);
}
void QuicConnectionManager::OnGoAway(const QuicGoAwayFrame& frame) {
  if(visitor_ != nullptr) visitor_->OnGoAway(frame);
}
void QuicConnectionManager::OnConnectionClosed(QuicErrorCode error,
    const std::string& error_details, ConnectionCloseSource source) {
  if(visitor_ != nullptr) visitor_->OnConnectionClosed(error,error_details,source);
}
void QuicConnectionManager::OnWriteBlocked() {
  if(visitor_ != nullptr) visitor_->OnWriteBlocked();
}
void QuicConnectionManager::OnSuccessfulVersionNegotiation(const QuicVersion& version) {
  if(visitor_ != nullptr) visitor_->OnSuccessfulVersionNegotiation(version);
}
void QuicConnectionManager::OnCanWrite() {
  if(visitor_ != nullptr) visitor_->OnCanWrite();
}
void QuicConnectionManager::OnCongestionWindowChange(QuicTime now) {
  if(visitor_ != nullptr) visitor_->OnCongestionWindowChange(now);
}
void QuicConnectionManager::OnConnectionMigration(PeerAddressChangeType type) {
  if(visitor_ != nullptr) visitor_->OnConnectionMigration(type);
}
void QuicConnectionManager::OnPathDegrading() {
  if(visitor_ != nullptr) visitor_->OnPathDegrading();
}
void QuicConnectionManager::PostProcessAfterData() {
  if(visitor_ != nullptr) visitor_->PostProcessAfterData();
}
void QuicConnectionManager::OnAckNeedsRetransmittableFrame() {
  if(visitor_ != nullptr) visitor_->OnAckNeedsRetransmittableFrame();
}
bool QuicConnectionManager::WillingAndAbleToWrite() const {
  if(visitor_ != nullptr) return visitor_->WillingAndAbleToWrite();
  return false;
}
bool QuicConnectionManager::HasPendingHandshake() const {
  if(visitor_ != nullptr) return visitor_->HasPendingHandshake();
  return false;
}
bool QuicConnectionManager::HasOpenDynamicStreams() const {
  if(visitor_ != nullptr) return visitor_->HasOpenDynamicStreams();
  return false;
}
void QuicConnectionManager::OnAckFrame(const QuicAckFrame& frame) {
  auto it = connections_.find(frame.subflow_id);
  if(it != connections_.end()) {
    // Acknowledge that a packet was received on the subflow, so we can
    // stop sending a NEW_SUBFLOW frame in every packet.
    it->second->StopSendingNewSubflowFrame();
  }
}
void QuicConnectionManager::OnHandshakeComplete() {
  // As soon as we have our keys set up, we can set up our QuicFramer
  // to decrypt/decode incoming and encrypt/encode outgoing subflow requests
  packet_handler_ = new QuicSubflowPacketHandler(
      InitialConnection()->supported_versions(),
      InitialConnection()->helper()->GetClock()->ApproximateNow(),
      InitialConnection()->perspective(),
      InitialConnection()->Framer()->CryptoContext(),
      false);

  // Add outgoing subflows
  for(const QuicSubflowDescriptor& descriptor: buffered_outgoing_subflow_attempts_) {
    TryAddingSubflow(descriptor);
  }
  buffered_outgoing_subflow_attempts_.clear();

  // Add incoming subflows
  for(std::pair<QuicSubflowDescriptor, std::unique_ptr<QuicReceivedPacket> >& incomingRequest: buffered_incoming_subflow_attempts_) {
    ProcessUdpPacket(
        incomingRequest.first.Self(),
        incomingRequest.first.Peer(),
        *incomingRequest.second);
  }
  buffered_incoming_subflow_attempts_.clear();
}


// QuicSubflowPacketHandler
void QuicConnectionManager::QuicSubflowPacketHandler::OnPacket() {}
bool QuicConnectionManager::QuicSubflowPacketHandler::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnUnauthenticatedHeader(const QuicPacketHeader& header) {return true;}
void QuicConnectionManager::QuicSubflowPacketHandler::OnError(QuicFramer* framer) {}
bool QuicConnectionManager::QuicSubflowPacketHandler::OnProtocolVersionMismatch(QuicVersion received_version) {return false; } //TODO is this possible?
void QuicConnectionManager::QuicSubflowPacketHandler::OnPublicResetPacket(const QuicPublicResetPacket& packet) {}
void QuicConnectionManager::QuicSubflowPacketHandler::OnVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& packet) {}
void QuicConnectionManager::QuicSubflowPacketHandler::OnDecryptedPacket(EncryptionLevel level) {}
bool QuicConnectionManager::QuicSubflowPacketHandler::OnPacketHeader(const QuicPacketHeader& header) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnStreamFrame(const QuicStreamFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnAckFrame(const QuicAckFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnStopWaitingFrame(const QuicStopWaitingFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnPaddingFrame(const QuicPaddingFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnPingFrame(const QuicPingFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnRstStreamFrame(const QuicRstStreamFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnGoAwayFrame(const QuicGoAwayFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnBlockedFrame(const QuicBlockedFrame& frame) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnNewSubflowFrame(const QuicNewSubflowFrame& frame) {
  ++n_new_subflow_frames_;
  subflow_id_ = frame.subflow_id;
  return true;
}
bool QuicConnectionManager::QuicSubflowPacketHandler::OnSubflowCloseFrame(const QuicSubflowCloseFrame& frame) { return true; }
void QuicConnectionManager::QuicSubflowPacketHandler::OnPacketComplete() {}


}
