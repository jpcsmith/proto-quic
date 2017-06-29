// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_connection_manager.h"
#include "net/quic/core/quic_connection.h"

#include <utility>
#include "net/quic/core/quic_packet_generator.h"
#include "net/quic/core/quic_packet_creator.h"

namespace net {

QuicConnectionManager::QuicConnectionManager(QuicConnection *connection)
    : connections_(std::map<QuicSubflowId, QuicConnection*>()),
      next_outgoing_subflow_id_(connection->perspective() == Perspective::IS_SERVER ? 2 : 3),
      packet_handler_(nullptr),
      current_subflow_id_(kInitialSubflowId) {
  AddConnection(connection->SubflowDescriptor(), kInitialSubflowId, connection);
  connection->set_visitor(this);
  // if the connection has already established keys, we can start accepting new
  // subflows right away.
  if(connection->SubflowState() == QuicConnection::SUBFLOW_OPEN) {
    InitializeSubflowPacketHandler();
  }
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

void QuicConnectionManager::AddPacketWriter(QuicSubflowDescriptor descriptor, QuicPacketWriter *writer) {
  packet_writer_map_[descriptor] = writer;
}

void QuicConnectionManager::CloseSubflow(QuicSubflowId id) {
  CloseConnection(id,SUBFLOW_OUTGOING);
}

void QuicConnectionManager::ProcessUdpPacket(const QuicSocketAddress& self_address,
                                   const QuicSocketAddress& peer_address,
                                   const QuicReceivedPacket& packet) {
  QuicSubflowDescriptor descriptor(self_address,peer_address);
  QUIC_LOG(INFO) << "ProcessUdpPacket(" << self_address.ToString() << ", " << peer_address.ToString() << ")";
  QUIC_LOG(INFO) << "subflow descriptor map entries:";
  for(auto it = subflow_descriptor_map_.begin(); it != subflow_descriptor_map_.end(); ++it) {
    QUIC_LOG(INFO) << "subflow descriptor=" << it->first.ToString() << " subflow id=" << it->second;
  }
  auto it = subflow_descriptor_map_.find(descriptor);

  // subflow already established
  if(it != subflow_descriptor_map_.end())
  {
    QUIC_LOG(INFO) << "Packet on subflow (" << QuicSubflowDescriptor(self_address,peer_address).ToString() << "): Forwarded to connection";
    connections_[it->second]->ProcessUdpPacket(self_address,peer_address,packet);
  }
  else
  {
    if(packet_handler_ == nullptr) {
      QUIC_LOG(INFO) << "Packet on subflow (" << QuicSubflowDescriptor(self_address,peer_address).ToString() << "): Buffered";
      // handshake not yet finished -> buffer request
      buffered_incoming_subflow_attempts_.push_back(
          std::pair<QuicSubflowDescriptor,std::unique_ptr<QuicReceivedPacket>>(
              QuicSubflowDescriptor(self_address,peer_address),packet.Clone()));
    } else {
      if(!packet_handler_->ProcessPacket(packet)) {
        QUIC_LOG(INFO) << "Packet on subflow (" << QuicSubflowDescriptor(self_address,peer_address).ToString() << "): Error (Cannot accept new subflow)";
        //TODO error handling
        return;
      }
      else
      {
        QUIC_LOG(INFO) << "Packet on subflow (" << QuicSubflowDescriptor(self_address,peer_address).ToString() << "): New incoming subflow (" << packet_handler_->GetLastSubflowId() << ")";
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
      descriptor,
      GetPacketWriter(descriptor),
      false,
      subflowId);
  connection->set_visitor(this);

  // Set the SubflowState depending on the SubflowDirection
  if(direction == SUBFLOW_OUTGOING) {
    connection->SetSubflowState(QuicConnection::SUBFLOW_OPEN_INITIATED);
    // Add NEW_SUBFLOW frame to every packet
    connection->PrependNewSubflowFrame(subflowId);
  } else {
    connection->SetSubflowState(QuicConnection::SUBFLOW_OPEN);
  }

  AddConnection(descriptor,subflowId,connection);
}

void QuicConnectionManager::AddConnection(QuicSubflowDescriptor descriptor, QuicSubflowId subflowId, QuicConnection *connection) {
  QUIC_LOG(INFO) << "Add connection: subflowId = " << subflowId << " subflowDescriptor = " << descriptor.ToString();
  connections_.insert(
      std::pair<QuicSubflowId, QuicConnection*>(
          subflowId,
          connection));
  subflow_descriptor_map_.insert(
      std::pair<QuicSubflowDescriptor, QuicSubflowId>(
          descriptor,
          subflowId));
  //connection->sent_packet_manager().SetSubflowId(subflowId);
}

void QuicConnectionManager::CloseConnection(QuicSubflowId subflowId, SubflowDirection direction) {
  QuicConnection *connection = connections_[subflowId];
  if(direction == SUBFLOW_INCOMING) {
    connection->RemovePrependedFrames();
    connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSED);
  } else {
    // Send connection close frame on this subflow.
    // TODO send on any subflow?
    connection->PrependSubflowCloseFrame(subflowId);
    connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSE_INITIATED);
  }

  RemoveConnection(subflowId);
}

void QuicConnectionManager::RemoveConnection(QuicSubflowId subflowId) {
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

QuicPacketWriter *QuicConnectionManager::GetPacketWriter(QuicSubflowDescriptor descriptor) {
  return packet_writer_map_[descriptor];
}

void QuicConnectionManager::InitializeSubflowPacketHandler() {
  packet_handler_ = new QuicSubflowPacketHandler(
        InitialConnection()->supported_versions(),
        InitialConnection()->helper()->GetClock()->ApproximateNow(), //TODO use same creation time for all framers?
        InitialConnection()->perspective(),
        InitialConnection()->Framer()->CryptoContext(),
        false,
        InitialConnection()->Framer()->version());
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
  for(auto it = connections_.begin(); it != connections_.end(); ++it) {
    // No need to notify visitor
    it->second->TearDownLocalConnectionState(error,error_details,source,false);
  }
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
    QuicConnection *connection = it->second;
    if(connection->SubflowState() == QuicConnection::SUBFLOW_OPEN_INITIATED) {
    // Acknowledge that a packet was received on the subflow, so we can
    // stop sending a NEW_SUBFLOW frame in every packet.
      connection->RemovePrependedFrames();
      connection->SetSubflowState(QuicConnection::SUBFLOW_OPEN);
    } else if(connection->SubflowState() == QuicConnection::SUBFLOW_OPEN) {
      // ignore
    } else if(connection->SubflowState() == QuicConnection::SUBFLOW_CLOSE_INITIATED && connection->SubflowCloseFrameReceived(frame.largest_observed)) {
      // Stop sending SUBFLOW_CLOSE frames //TODO necessary?
      connection->RemovePrependedFrames();
      connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSED);
    } else if(connection->SubflowState() == QuicConnection::SUBFLOW_CLOSED) {
      // ignore
    }
  } else {
    //TODO error handling
  }
}
void QuicConnectionManager::OnHandshakeComplete() {
  // As soon as we have our keys set up, we can set up our QuicFramer
  // to decrypt/decode incoming and encrypt/encode outgoing subflow requests
  InitializeSubflowPacketHandler();

  InitialConnection()->SetSubflowState(QuicConnection::SUBFLOW_OPEN);

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
void QuicConnectionManager::OnSubflowCloseFrame(const QuicSubflowCloseFrame& frame) {
  auto it = connections_.find(frame.subflow_id);
    if(it != connections_.end()) {
      QuicConnection *connection = it->second;
      connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSED);
    } else {
      //TODO error handling
    }
}


// QuicSubflowPacketHandler
void QuicConnectionManager::QuicSubflowPacketHandler::OnPacket() {}
bool QuicConnectionManager::QuicSubflowPacketHandler::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) { return true; }
bool QuicConnectionManager::QuicSubflowPacketHandler::OnUnauthenticatedHeader(const QuicPacketHeader& header) { return true;}
void QuicConnectionManager::QuicSubflowPacketHandler::OnError(QuicFramer* framer) {}
bool QuicConnectionManager::QuicSubflowPacketHandler::OnProtocolVersionMismatch(QuicVersion received_version) {return true; }
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
