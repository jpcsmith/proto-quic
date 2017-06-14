// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_connection_manager.h"
#include <utility>

namespace net {

QuicConnectionManager::QuicConnectionManager(QuicConnection *connection)
    : connections_(std::map<QuicSubflowId, QuicConnection*>()),
      next_outgoing_subflow_id_(connection->perspective() == Perspective::IS_SERVER ? 2 : 3) {
  connections_.insert(
      std::pair<QuicSubflowId, QuicConnection*>(kInitialSubflowId,
          connection));
  connection->set_visitor(this);
}

QuicConnectionManager::~QuicConnectionManager() {
}

void QuicConnectionManager::tryAddingSubflow(QuicSubflowDescriptor descriptor) {

  // register attempt to open subflow
  subflow_attempt_map_.insert(
      std::pair<QuicSubflowDescriptor, QuicSubflowCreationAttempt>(
          descriptor,new QuicSubflowCreationAttempt(descriptor,
              GetNextOutgoingSubflowId(),
              this,
              clock_,
              alarm_factory_)));

  // set alarm to go off in case no ack was received after timeout.

  // if ack was received, add subflow connection to the active connections

  // send packet on subflow containing new_subflow frame
}

void OnSubflowCreationFailed(QuicSubflowId id) {
  // remove from subflow attempt map
}

void QuicConnectionManager::closeSubflow(QuicSubflowId id) {
  // remove from subflow map
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
    // subflow attempt was made
    it = subflow_attempt_map_.find(descriptor);
    if(it != subflow_attempt_map_.end())
    {
      // if packet is ack packet for packet with new_subflow frame -> add subflow
      // else discard packet
    }
    // no subflow attempt was made
    else
    {
      // if packet consists of new_subflow frame -> add subflow & send ack (with timer)
    }
  }
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

}
