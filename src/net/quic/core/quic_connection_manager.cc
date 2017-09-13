// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_connection_manager.h"
#include "net/quic/core/quic_connection.h"

#include <utility>
#include "net/quic/core/quic_packet_generator.h"
#include "net/quic/core/quic_packet_creator.h"
#include "net/quic/core/congestion_control/roundrobin_algorithm.h"
#include "net/quic/core/congestion_control/mtcp_send_algorithm.h"
#include "net/quic/core/congestion_control/olia_send_algorithm.h"

namespace net {

QuicConnectionManager::QuicConnectionManager(QuicConnection *connection)
    : goaway_sent_(false), goaway_received_(false), connections_(
        std::map<QuicSubflowId, QuicConnection*>()), next_outgoing_subflow_id_(
        connection->perspective() == Perspective::IS_SERVER ? 2 : 3), current_subflow_id_(
        kInitialSubflowId), next_subflow_id_(0), multipath_send_algorithm_(
        new OliaSendAlgorithm(new RoundRobinAlgorithm())) {
  connection->SetMultipathSendAlgorithm(GetSendAlgorithm());
  AddConnection(connection->SubflowDescriptor(), kInitialSubflowId, connection);
  connection->set_visitor(this);
}

QuicConnectionManager::~QuicConnectionManager() {
  // delete all connections but the first (first connection
  // is not owned by the connection manager)
  for (auto &it : connections_) {
    if (it.second != InitialConnection()) {
      delete it.second;
    }
  }
  connections_.clear();
}

void QuicConnectionManager::CloseConnection(QuicErrorCode error,
    const std::string& details,
    ConnectionCloseBehavior connection_close_behavior) {
  CurrentConnection()->CloseConnection(error, details,
      connection_close_behavior);
}

bool QuicConnectionManager::HasQueuedData() {
  bool hasQueuedData = false;
  for (auto it = connections_.begin(); it != connections_.end(); ++it) {
    if (it->second->HasQueuedData()) {
      hasQueuedData = true;
    }
  }
  return hasQueuedData;
}

void QuicConnectionManager::SetNumOpenStreams(size_t num_streams) {
  for (auto it = connections_.begin(); it != connections_.end(); ++it) {
    it->second->SetNumOpenStreams(num_streams);
  }
}

QuicConsumedData QuicConnectionManager::SendStreamData(QuicStreamId id,
    QuicIOVector iov, QuicStreamOffset offset, StreamSendingState state,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener,
    QuicConnection* connection) {
  QUIC_LOG(INFO)
      << "SendStreamData(id = " << id << ", length = " << iov.total_length << ", subflow id = "
          << (connection == nullptr ?
              "null connection" : std::to_string(connection->GetSubflowId()))
          << ") enclvl = "
          << (connection == nullptr ?
              "nullptr" :
              (connection->encryption_level() == ENCRYPTION_FORWARD_SECURE ?
                  "fwsec" :
                  (connection->encryption_level() == ENCRYPTION_INITIAL ?
                      "initsec" : "unencrypted")));
  // Workaround because SendAlgorithm::InitialEncryptionEstablished is called
  // after the SHLO was sent by the server.
  if (id == 1 && connection != nullptr
      && connection->perspective() == Perspective::IS_SERVER
      && connection->encryption_level() == ENCRYPTION_INITIAL
      && GetSendAlgorithm()->GetEncryptionLevel(connection->SubflowDescriptor())
          != ENCRYPTION_INITIAL) {
    GetSendAlgorithm()->InitialEncryptionEstablished(
        connection->SubflowDescriptor());
  }
  QuicSubflowDescriptor hint =
      connection != nullptr ?
          connection->SubflowDescriptor() : QuicSubflowDescriptor();
  MultipathSendAlgorithmInterface::SendReason reason =
      MultipathSendAlgorithmInterface::SendReason::ENCRYPTED_TRANSMISSION;
  if (connection != nullptr
      && connection->encryption_level() == ENCRYPTION_NONE) {
    reason =
        MultipathSendAlgorithmInterface::SendReason::UNENCRYPTED_TRANSMISSION;
  }
  const QuicSubflowDescriptor& descriptor =
      GetSendAlgorithm()->GetNextStreamFrameSubflow(id, iov.total_length, hint,
          reason);
  p("Using subflow", descriptor);
  return GetConnection(descriptor)->SendStreamData(id, iov, offset, state,
      ack_listener);
}

void QuicConnectionManager::SendRstStream(QuicStreamId id,
    QuicRstStreamErrorCode error, QuicStreamOffset bytes_written) {
  QUIC_LOG(INFO) << "SendRstStream(id = " << id << ")";
  QuicRstStreamFrame* rstStreamFrame = new QuicRstStreamFrame(id, error,
      bytes_written);
  const QuicSubflowDescriptor& descriptor =
      GetSendAlgorithm()->GetNextControlFrameSubflow(QuicFrame(rstStreamFrame),
          QuicSubflowDescriptor());
  delete rstStreamFrame;
  p("Using subflow", descriptor);
  GetConnection(descriptor)->SendRstStream(id, error, bytes_written);
}

void QuicConnectionManager::SendBlocked(QuicStreamId id) {
  QUIC_LOG(INFO) << "SendBlocked(id = " << id << ")";
  QuicBlockedFrame* blockedFrame = new QuicBlockedFrame(id);
  const QuicSubflowDescriptor& descriptor =
      GetSendAlgorithm()->GetNextControlFrameSubflow(QuicFrame(blockedFrame),
          QuicSubflowDescriptor());
  delete blockedFrame;
  p("Using subflow", descriptor);
  GetConnection(descriptor)->SendBlocked(id);
}

void QuicConnectionManager::SendWindowUpdate(QuicStreamId id,
    QuicStreamOffset byte_offset) {
  QUIC_LOG(INFO) << "SendWindowUpdate(id = " << id << ")";
  QuicWindowUpdateFrame *windowUpdateFrame = new QuicWindowUpdateFrame(id,
      byte_offset);
  const QuicSubflowDescriptor& descriptor =
      GetSendAlgorithm()->GetNextControlFrameSubflow(
          QuicFrame(windowUpdateFrame), QuicSubflowDescriptor());
  delete windowUpdateFrame;
  p("Using subflow", descriptor);
  GetConnection(descriptor)->SendWindowUpdate(id, byte_offset);
}

void QuicConnectionManager::SendGoAway(QuicErrorCode error,
    QuicStreamId last_good_stream_id, const std::string& reason) {
  QUIC_LOG(INFO) << "SendGoAway(reason = " << reason << ")";
  if (goaway_sent_) {
    return;
  }
  goaway_sent_ = true;
  QuicGoAwayFrame* goAwayFrame = new QuicGoAwayFrame(error, last_good_stream_id,
      reason);
  const QuicSubflowDescriptor& descriptor =
      GetSendAlgorithm()->GetNextControlFrameSubflow(QuicFrame(goAwayFrame),
          QuicSubflowDescriptor());
  delete goAwayFrame;
  p("Using subflow", descriptor);
  GetConnection(descriptor)->SendGoAway(error, last_good_stream_id, reason);
}

void QuicConnectionManager::TryAddingSubflow(QuicSubflowDescriptor descriptor) {
  OpenConnection(descriptor, SUBFLOW_OUTGOING);
  AssignConnection(descriptor, GetNextOutgoingSubflowId(), SUBFLOW_OUTGOING);
}

void QuicConnectionManager::AddPacketWriter(QuicSubflowDescriptor descriptor,
    QuicPacketWriter *writer) {
  packet_writer_map_[descriptor] = writer;
}

// Tries to close a subflow. Changes its state to SUBFLOW_CLOSE_INITIATED
// and starts sending SUBFLOW_CLOSE frames until a packet containing a
// SUBFLOW_CLOSE frame is acknowledged.
void QuicConnectionManager::CloseSubflow(QuicSubflowId id) {
  CloseConnection(id, SUBFLOW_OUTGOING);
}

void QuicConnectionManager::ProcessUdpPacket(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address, const QuicReceivedPacket& packet) {
  QuicSubflowDescriptor descriptor(self_address, peer_address);

  std::string s;
  bool first = true;
  for (auto debugIt : subflow_descriptor_map_) {
    s += (first ? "" : ", ") + std::to_string(debugIt.second);
    first = false;
  }
  QUIC_LOG(INFO)
      << "ProcessUdpPacket(" << self_address.ToString() << ", "
          << peer_address.ToString() << "), subflows: " << s;

  auto it = subflow_descriptor_map_.find(descriptor);
  // subflow already established
  if (it != subflow_descriptor_map_.end()) {
    QUIC_LOG(INFO) << "Packet forwarded to: " << it->second;
    connections_[it->second]->ProcessUdpPacket(self_address, peer_address,
        packet);
  } else {
    if (unassigned_subflow_map_.find(descriptor)
        != unassigned_subflow_map_.end()) {
      QUIC_LOG(INFO) << "Packet forwarded to unassigned subflow";
    } else {
      QUIC_LOG(INFO) << "Packet forwarded to new incoming subflow";
      OpenConnection(descriptor, SUBFLOW_INCOMING);
    }
    unassigned_subflow_map_[descriptor]->ProcessUdpPacket(self_address,
        peer_address, packet);
  }
}

void QuicConnectionManager::OnHandshakeInitiated(QuicConnection* connection) {
  multipath_send_algorithm_->InitialEncryptionEstablished(
      connection->SubflowDescriptor());
}

void QuicConnectionManager::OnHandshakeComplete(QuicConnection* connection) {
  multipath_send_algorithm_->ForwardSecureEncryptionEstablished(
      connection->SubflowDescriptor());
}

void QuicConnectionManager::AckReceivedForSubflow(QuicConnection* connection,
    const QuicAckFrame& frame) {

  if (connection->SubflowState() == QuicConnection::SUBFLOW_OPEN_INITIATED &&
  // We established forward secure encryption.
      connection->encryption_level() == ENCRYPTION_FORWARD_SECURE &&
      // We have established a common non-zero subflow id.
      connection->GetSubflowId() == frame.subflow_id && frame.subflow_id != 0 &&
      // Every encrypted packet contains the NEW_SUBFLOW frame
      connection->AcknowledgingEncryptedPacket(frame.largest_observed)) {
    // Acknowledge that a packet containing a NEW_SUBFLOW frame was received
    // on the subflow, so we can stop sending a NEW_SUBFLOW frame in every packet.
    connection->RemovePrependedFrames();
    connection->SetSubflowState(QuicConnection::SUBFLOW_OPEN);
  } else if (connection->SubflowState() == QuicConnection::SUBFLOW_OPEN) {
    // ignore
  } else if (connection->SubflowState()
      == QuicConnection::SUBFLOW_CLOSE_INITIATED
      && connection->SubflowCloseFrameReceived(frame.largest_observed)) {
    // Stop sending SUBFLOW_CLOSE frames //TODO necessary?
    connection->RemovePrependedFrames();
    connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSED);
  } else if (connection->SubflowState() == QuicConnection::SUBFLOW_CLOSED) {
    // ignore
  }
}

void QuicConnectionManager::OpenConnection(QuicSubflowDescriptor descriptor,
    SubflowDirection direction) {
  // Create new connection
  QuicConnection *connection = InitialConnection()->CloneToSubflow(descriptor,
      GetPacketWriter(descriptor), false, 0, GetSendAlgorithm());
  connection->set_visitor(this);
  connection->SetSubflowState(QuicConnection::SUBFLOW_OPEN_INITIATED);
  QUIC_LOG(INFO) << "test";
  AddUnassignedConnection(descriptor, connection);

  if (direction == SUBFLOW_OUTGOING) {
    visitor_->StartCryptoConnect(connection);
  }
}

void QuicConnectionManager::AssignConnection(QuicSubflowDescriptor descriptor,
    QuicSubflowId subflowId, SubflowDirection direction) {
  // Check the validity of the subflow id
  std::string detailed_error;
  if (!IsSubflowIdValid(subflowId, direction, &detailed_error)) {
    QUIC_LOG(INFO)
            << "Error assigning a subflow id to a connection (" + detailed_error
                + ")";
    return;
  }

  // Store the connection with the provided subflow id
  DCHECK(
      unassigned_subflow_map_.find(descriptor) != unassigned_subflow_map_.end());
  QuicConnection *connection = unassigned_subflow_map_[descriptor];
  RemoveUnassignedConnection(descriptor);
  AddConnection(descriptor, subflowId, connection);
  connection->SetSubflowId(subflowId);

  if (direction == SUBFLOW_OUTGOING) {
    // Add NEW_SUBFLOW frame to every packet
    connection->PrependNewSubflowFrame(subflowId);
  } else {
    // As soon as we have received a NEW_SUBFLOW frame we consider the
    // connection as open.
    connection->SetSubflowState(QuicConnection::SUBFLOW_OPEN);
  }
}

void QuicConnectionManager::AddConnection(QuicSubflowDescriptor descriptor,
    QuicSubflowId subflowId, QuicConnection *connection) {
  QUIC_LOG(INFO)
      << "Adding connection: subflowId=" << subflowId << " subflowDescriptor="
          << descriptor.ToString() << " connection=" << (long long) connection;
  connections_.insert(
      std::pair<QuicSubflowId, QuicConnection*>(subflowId, connection));
  subflow_descriptor_map_.insert(
      std::pair<QuicSubflowDescriptor, QuicSubflowId>(descriptor, subflowId));

  // Try setting the current subflow id again now that we added a connection.
  if (next_subflow_id_ != 0) {
    set_current_subflow_id(next_subflow_id_);
  }
}

void QuicConnectionManager::AddUnassignedConnection(
    QuicSubflowDescriptor descriptor, QuicConnection *connection) {
  QUIC_LOG(INFO)
      << "Adding unassigned connection: subflowDescriptor="
          << descriptor.ToString();
  unassigned_subflow_map_.insert(
      std::pair<QuicSubflowDescriptor, QuicConnection*>(descriptor,
          connection));
}

void QuicConnectionManager::RemoveUnassignedConnection(
    QuicSubflowDescriptor descriptor) {
  QUIC_LOG(INFO)
      << "Removing unassigned connection: subflowDescriptor="
          << descriptor.ToString();
  unassigned_subflow_map_.erase(descriptor);
}

void QuicConnectionManager::CloseConnection(QuicSubflowId subflowId,
    SubflowDirection direction) {
  QuicConnection *connection = connections_[subflowId];
  if (direction == SUBFLOW_INCOMING) {
    connection->RemovePrependedFrames();
    connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSED);
  } else {
    // Send connection close frame on this subflow.
    // TODO send on any subflow?
    connection->PrependSubflowCloseFrame(subflowId);
    connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSE_INITIATED);
  }

  //TODO remove connections or just set the state to SUBFLOW_CLOSED?
  //RemoveConnection(subflowId);
}

void QuicConnectionManager::RemoveConnection(QuicSubflowId subflowId) {
  // remove connection
  connections_.erase(subflowId);

  // remove from subflow map
  QuicSubflowDescriptor descriptor;
  for (const auto& it : subflow_descriptor_map_) {
    if (it.second == subflowId) {
      descriptor = it.first;
      break;
    }
  }
  if (descriptor.IsInitialized()) {
    subflow_descriptor_map_.erase(descriptor);
  }
}

bool QuicConnectionManager::IsSubflowIdValid(QuicSubflowId subflowId,
    SubflowDirection direction, std::string* detailed_error) {
  if (direction == SUBFLOW_OUTGOING) {
    if (subflowId % 2 != next_outgoing_subflow_id_ % 2) {
      *detailed_error = "The subflow id: " + std::to_string(subflowId)
          + " cannot be used for an outgoing connection.";
      return false;
    }
  } else {
    if (subflowId % 2 != (next_outgoing_subflow_id_ + 1) % 2) {
      *detailed_error = "The subflow id: " + std::to_string(subflowId)
          + " cannot be used for an incoming connection.";
      return false;
    }
  }
  if (connections_.find(subflowId) != connections_.end()) {
    *detailed_error = "The subflow id: " + std::to_string(subflowId)
        + " is already used by a different subflow.";
    return false;
  }
  return true;
}

QuicPacketWriter *QuicConnectionManager::GetPacketWriter(
    QuicSubflowDescriptor descriptor) {
  return packet_writer_map_[descriptor];
}

QuicSubflowId QuicConnectionManager::GetNextOutgoingSubflowId() {
  QuicSubflowId id = next_outgoing_subflow_id_;
  next_outgoing_subflow_id_ += 2;
  return id;
}

QuicConnection* QuicConnectionManager::GetConnection(
    QuicSubflowId subflowId) const {
  auto it = connections_.find(subflowId);
  if (it != connections_.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

QuicConnection* QuicConnectionManager::GetConnection(
    const QuicSubflowDescriptor& descriptor) const {
  if (subflow_descriptor_map_.find(descriptor)
      != subflow_descriptor_map_.end()) {
    QuicSubflowId subflowId = subflow_descriptor_map_.find(descriptor)->second;
    if (connections_.find(subflowId) != connections_.end()) {
      return connections_.find(subflowId)->second;
    }
  }
  if (unassigned_subflow_map_.find(descriptor)
      != unassigned_subflow_map_.end()) {
    return unassigned_subflow_map_.find(descriptor)->second;
  }
  return nullptr;
}

void QuicConnectionManager::OnStreamFrame(QuicConnection* connection,
    const QuicStreamFrame& frame) {
  if (visitor_)
    visitor_->OnStreamFrame(frame, connection);
}
void QuicConnectionManager::OnWindowUpdateFrame(QuicConnection* connection,
    const QuicWindowUpdateFrame& frame) {
  if (visitor_)
    visitor_->OnWindowUpdateFrame(frame);
}
void QuicConnectionManager::OnBlockedFrame(QuicConnection* connection,
    const QuicBlockedFrame& frame) {
  if (visitor_)
    visitor_->OnBlockedFrame(frame);
}
void QuicConnectionManager::OnRstStream(QuicConnection* connection,
    const QuicRstStreamFrame& frame) {
  if (visitor_)
    visitor_->OnRstStream(frame);
}
void QuicConnectionManager::OnGoAway(QuicConnection* connection,
    const QuicGoAwayFrame& frame) {
  goaway_received_ = true;
  if (visitor_)
    visitor_->OnGoAway(frame);
}
void QuicConnectionManager::OnConnectionClosed(QuicConnection* connection,
    QuicErrorCode error, const std::string& error_details,
    ConnectionCloseSource source) {
  for (auto it = connections_.begin(); it != connections_.end(); ++it) {
    if (it->second != connection) {
      // No need to notify visitor
      it->second->TearDownLocalConnectionState(error, error_details, source,
          false);
    }
  }
  for (auto it2 = unassigned_subflow_map_.begin();
      it2 != unassigned_subflow_map_.end(); ++it2) {
    if (it2->second != connection) {
      // No need to notify visitor
      it2->second->TearDownLocalConnectionState(error, error_details, source,
          false);
    }
  }
  if (visitor_)
    visitor_->OnConnectionClosed(error, error_details, source);
}
void QuicConnectionManager::OnWriteBlocked(QuicConnection* connection) {
  //TODO maybe use a different subflow if this one is write blocked
  if (visitor_)
    visitor_->OnWriteBlocked(connection);
}
void QuicConnectionManager::OnSuccessfulVersionNegotiation(
    QuicConnection* connection, const QuicVersion& version) {
  if (visitor_)
    visitor_->OnSuccessfulVersionNegotiation(version);
}
void QuicConnectionManager::OnCanWrite(QuicConnection* connection) {
  if (visitor_)
    visitor_->OnCanWrite(connection);
}
void QuicConnectionManager::OnCongestionWindowChange(QuicConnection* connection,
    QuicTime now) {
  if (visitor_)
    visitor_->OnCongestionWindowChange(connection, now);
}
void QuicConnectionManager::OnConnectionMigration(QuicConnection* connection,
    PeerAddressChangeType type) {
  if (visitor_)
    visitor_->OnConnectionMigration(type);
}
void QuicConnectionManager::OnPathDegrading(QuicConnection* connection) {
  //TODO only send if all paths are degrading?
  if (visitor_)
    visitor_->OnPathDegrading();
}
void QuicConnectionManager::PostProcessAfterData(QuicConnection* connection) {
  if (visitor_)
    visitor_->PostProcessAfterData();
}
void QuicConnectionManager::OnAckNeedsRetransmittableFrame(
    QuicConnection* connection) {
  if (visitor_)
    visitor_->OnAckNeedsRetransmittableFrame();
}
bool QuicConnectionManager::WillingAndAbleToWrite(
    QuicConnection* connection) const {
  if (visitor_)
    return visitor_->WillingAndAbleToWrite();
  return false;
}
bool QuicConnectionManager::HasPendingHandshake(
    QuicConnection* connection) const {
  if (visitor_)
    return visitor_->HasPendingHandshake();
  return false;
}
bool QuicConnectionManager::HasOpenDynamicStreams(
    QuicConnection* connection) const {
  if (visitor_)
    return visitor_->HasOpenDynamicStreams();
  return false;
}
bool QuicConnectionManager::OnAckFrame(QuicConnection* connection,
    const QuicAckFrame& frame, const QuicTime& arrival_time_of_packet) {
  if (frame.subflow_id == 0 || frame.subflow_id == connection->GetSubflowId()) {
    // The ACK frame is for a packet that was sent on the same subflow.
    // We should only receive an ACK frame with subflow id 0 for a handshake
    // message on the same subflow where the packet was sent.
    if (!connection->HandleIncomingAckFrame(frame, arrival_time_of_packet)) {
      return false;
    }
    AckReceivedForSubflow(connection, frame);

  } else if (connections_.find(frame.subflow_id) != connections_.end()) {
    // Forward the ack frame to the corresponding connection.
    QuicConnection *ackFrameConnection =
        connections_.find(frame.subflow_id)->second;
    if (!ackFrameConnection->HandleIncomingAckFrame(frame,
        arrival_time_of_packet)) {
      return false;
    }
    AckReceivedForSubflow(ackFrameConnection, frame);

  } else {
    //TODO error handling
    return true;
  }
  return true;
}
void QuicConnectionManager::OnNewSubflowFrame(QuicConnection* connection,
    const QuicNewSubflowFrame& frame) {
  if (unassigned_subflow_map_.find(connection->SubflowDescriptor())
      != unassigned_subflow_map_.end()) {
    // If we receive a NEW_SUBFLOW frame, we are able to decrypt messages since
    // NEW_SUBFLOW frames are only sent encrypted. Thus both endpoints have established
    // a forward secure connection and share the same subflow id. So we change the
    // SubflowState to SUBFLOW_OPEN.
    AssignConnection(connection->SubflowDescriptor(), frame.subflow_id,
        SUBFLOW_INCOMING);
  } else {
    //ignore new subflow frames on subflows that already established their subflow id.
  }
}
void QuicConnectionManager::OnSubflowCloseFrame(QuicConnection* connection,
    const QuicSubflowCloseFrame& frame) {
  auto it = connections_.find(frame.subflow_id);
  if (it != connections_.end()) {
    QuicConnection *connection = it->second;
    connection->SetSubflowState(QuicConnection::SUBFLOW_CLOSED);
  } else {
    //TODO error handling
  }
}
QuicFrames QuicConnectionManager::GetUpdatedAckFrames(
    QuicConnection* connection) {
  QuicTime now = AnyConnection()->clock()->ApproximateNow();
  QuicFrames frames;
  uint32_t nAckFrames = 0;

  std::list<QuicSubflowDescriptor> usedSubflows;
  // Always send own ACK frame.
  if (connection->ack_frame_updated()) {
    frames.push_back(connection->GetUpdatedAckFrame(now));
    usedSubflows.push_back(connection->SubflowDescriptor());
    ++nAckFrames;
  }

  // Only allow sending ACK frames from different subflows if we already
  // established a secure connection.
  if (connection->encryption_level() == ENCRYPTION_FORWARD_SECURE) {

    // Only add ACK frames from connections that have already established
    // a subflow (SUBFLOW_OPEN).
    const std::list<QuicSubflowDescriptor>& ackFrameSubflows =
        multipath_send_algorithm_->AppendAckFrames(
            connection->SubflowDescriptor());

    for (auto it = ackFrameSubflows.begin();
        it != ackFrameSubflows.end() && nAckFrames < kMaxAckFramesPerResponse;
        ++it) {
      QuicConnection* subflow = GetConnection(*it);
      if (subflow != connection && subflow->ack_frame_updated()) {
        ++nAckFrames;
        frames.push_back(subflow->GetUpdatedAckFrame(now));
        usedSubflows.push_back(*it);
      }
    }
  }
  multipath_send_algorithm_->AckFramesAppended(usedSubflows);
  return frames;
}

void QuicConnectionManager::OnAckFrameUpdated(QuicConnection* connection) {
  multipath_send_algorithm_->OnAckFrameUpdated(connection->SubflowDescriptor());
}

void QuicConnectionManager::OnRetransmission(QuicConnection* connection,
    const QuicTransmissionInfo& transmission_info) {
  const QuicSubflowDescriptor& descriptor =
      multipath_send_algorithm_->GetNextRetransmissionSubflow(transmission_info,
          connection->SubflowDescriptor());
  GetConnection(descriptor)->RetransmitFrames(
      transmission_info.retransmittable_frames);
}

}
