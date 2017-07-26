// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_NET_QUIC_CONNECTION_MANAGER_H_
#define NET_QUIC_CORE_NET_QUIC_CONNECTION_MANAGER_H_

#include "base/macros.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"
#include "net/quic/core/frames/quic_stream_frame.h"
#include "net/quic/core/frames/quic_window_update_frame.h"
#include "net/quic/core/frames/quic_blocked_frame.h"
#include "net/quic/core/frames/quic_rst_stream_frame.h"
#include "net/quic/core/frames/quic_goaway_frame.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/quic_versions.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_alarm.h"

namespace net {

class QUIC_EXPORT_PRIVATE QuicConnectionManagerVisitorInterface {
public:
  virtual ~QuicConnectionManagerVisitorInterface() {}

  // A simple visitor interface for dealing with a data frame.
  virtual void OnStreamFrame(const QuicStreamFrame& frame, QuicConnection* connection) = 0;

  // The session should process the WINDOW_UPDATE frame, adjusting both stream
  // and connection level flow control windows.
  virtual void OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) = 0;

  // A BLOCKED frame indicates the peer is flow control blocked
  // on a specified stream.
  virtual void OnBlockedFrame(const QuicBlockedFrame& frame) = 0;

  // Called when the stream is reset by the peer.
  virtual void OnRstStream(const QuicRstStreamFrame& frame) = 0;

  // Called when the connection is going away according to the peer.
  virtual void OnGoAway(const QuicGoAwayFrame& frame) = 0;

  // Called when the connection is closed either locally by the framer, or
  // remotely by the peer.
  virtual void OnConnectionClosed(QuicErrorCode error,
                                  const std::string& error_details,
                                  ConnectionCloseSource source) = 0;

  // Called when the connection failed to write because the socket was blocked.
  virtual void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer) = 0;

  // Called once a specific QUIC version is agreed by both endpoints.
  virtual void OnSuccessfulVersionNegotiation(const QuicVersion& version) = 0;

  // Called when a blocked socket becomes writable.
  virtual void OnCanWrite(QuicConnection* connection) = 0;

  // Called when the connection experiences a change in congestion window.
  virtual void OnCongestionWindowChange(QuicConnection* connection, QuicTime now) = 0;

  // Called when the connection receives a packet from a migrated client.
  virtual void OnConnectionMigration(PeerAddressChangeType type) = 0;

  // Called when the peer seems unreachable over the current path.
  virtual void OnPathDegrading() = 0;

  // Called after OnStreamFrame, OnRstStream, OnGoAway, OnWindowUpdateFrame,
  // OnBlockedFrame, and OnCanWrite to allow post-processing once the work has
  // been done.
  virtual void PostProcessAfterData() = 0;

  // Called when the connection sends ack after
  // kMaxConsecutiveNonRetransmittablePackets consecutive not retransmittable
  // packets sent. To instigate an ack from peer, a retransmittable frame needs
  // to be added.
  virtual void OnAckNeedsRetransmittableFrame() = 0;

  // Called to ask if the visitor wants to schedule write resumption as it both
  // has pending data to write, and is able to write (e.g. based on flow control
  // limits).
  // Writes may be pending because they were write-blocked, congestion-throttled
  // or yielded to other connections.
  virtual bool WillingAndAbleToWrite() const = 0;

  // Called to ask if any handshake messages are pending in this visitor.
  virtual bool HasPendingHandshake() const = 0;

  // Called to ask if any streams are open in this visitor, excluding the
  // reserved crypto and headers stream.
  virtual bool HasOpenDynamicStreams() const = 0;

  // Called to start sending crypto handshakes on this connection.
  virtual void StartCryptoConnect(QuicConnection* connection) = 0;
};

class QUIC_EXPORT_PRIVATE QuicConnectionManager: public QuicConnectionVisitorInterface {
public:
  QuicConnectionManager(QuicConnection *connection);
  ~QuicConnectionManager() override;

  void set_visitor(QuicConnectionManagerVisitorInterface* visitor) {
    visitor_ = visitor;
  }

  // Returns the initially created connection, which was passed to the session
  // in the constructor.
  QuicConnection *InitialConnection() const {
    return connections_.at(kInitialSubflowId);
  }
  // Returns the connection that was marked as the currently active connection.
  QuicConnection *CurrentConnection() const {
    auto it = connections_.find(current_subflow_id_);
    if(it == connections_.end()) {
      QUIC_LOG(INFO) << "CurrentConnection() tries to access subflow " << current_subflow_id_;
      return nullptr;
    }
    return it->second;
  }
  // Returns a connection on some subflow.
  QuicConnection *AnyConnection() const {
    QUIC_BUG_IF(connections_.size()==0) << "There are no connections";
    return connections_.begin()->second;
  }
  // Returns a connection on a specific subflow.
  QuicConnection *ConnectionOfSubflow(QuicSubflowDescriptor descriptor) {
    return connections_[subflow_descriptor_map_[descriptor]];
  }

  // Marks the connection with the subflow id |id| as the currently active connection.
  // If the connection doesn't exist yet, the current connection will be set to
  // the new connection as soon as possible.
  void set_current_subflow_id(QuicSubflowId id) {
    if(connections_.find(id) == connections_.end()) {
      next_subflow_id_ = id;
    } else {
      QUIC_LOG(INFO) << "CurrentSubflow = " << id;
      current_subflow_id_ = id;
      next_subflow_id_ = 0;
    }
  }

  // Flow control
  QuicTime::Delta SmoothedRttForFlowController() {
    //TODO correctly handle flow control
    return InitialConnection()->sent_packet_manager().GetRttStats()->smoothed_rtt();
  }

  // Debugging output
  void PrintDebuggingInformation() {
    std::string s;
    for(auto it: subflow_descriptor_map_) {
      QuicConnection* connection = connections_.find(it.second)->second;
      s = s + it.first.ToString() + ": " + connection->ToString() + "\n";
    }
    QUIC_LOG(INFO) << s;
  }

  // QUIC connection control
  void CloseConnection(
      QuicErrorCode error,
      const std::string& details,
      ConnectionCloseBehavior connection_close_behavior);
  bool HasQueuedData();
  void SetNumOpenStreams(size_t num_streams);
  virtual QuicConsumedData SendStreamData(
      QuicStreamId id,
      QuicIOVector iov,
      QuicStreamOffset offset,
      StreamSendingState state,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener,
      QuicConnection* connection);
  virtual void SendRstStream(QuicStreamId id,
                             QuicRstStreamErrorCode error,
                             QuicStreamOffset bytes_written);
  virtual void SendBlocked(QuicStreamId id);
  virtual void SendWindowUpdate(QuicStreamId id, QuicStreamOffset byte_offset);
  virtual void SendGoAway(QuicErrorCode error,
                          QuicStreamId last_good_stream_id,
                          const std::string& reason);
  bool goaway_sent() const { return goaway_sent_; }
  bool goaway_received() const { return goaway_received_; }

  // Subflow control
  void TryAddingSubflow(QuicSubflowDescriptor descriptor);
  void AddPacketWriter(QuicSubflowDescriptor descriptor, QuicPacketWriter *writer);
  void CloseSubflow(QuicSubflowId id);
  void ProcessUdpPacket(const QuicSocketAddress& self_address,
                                     const QuicSocketAddress& peer_address,
                                     const QuicReceivedPacket& packet);

  // Called when the CryptoHandshakeEvent HANDSHAKE_CONFIRMED was received.
  void OnHandshakeComplete();

  // QuicConnectionVisitorInterface
  void OnStreamFrame(QuicConnection* connection, const QuicStreamFrame& frame) override;
  void OnWindowUpdateFrame(QuicConnection* connection, const QuicWindowUpdateFrame& frame) override;
  void OnBlockedFrame(QuicConnection* connection, const QuicBlockedFrame& frame) override;
  void OnRstStream(QuicConnection* connection, const QuicRstStreamFrame& frame) override;
  void OnGoAway(QuicConnection* connection, const QuicGoAwayFrame& frame) override;
  void OnConnectionClosed(QuicConnection* connection,
                                  QuicErrorCode error,
                                  const std::string& error_details,
                                  ConnectionCloseSource source) override;
  void OnWriteBlocked(QuicConnection* connection) override;
  void OnSuccessfulVersionNegotiation(QuicConnection* connection, const QuicVersion& version) override;
  void OnCanWrite(QuicConnection* connection) override;
  void OnCongestionWindowChange(QuicConnection* connection, QuicTime now) override;
  void OnConnectionMigration(QuicConnection* connection, PeerAddressChangeType type) override;
  void OnPathDegrading(QuicConnection* connection) override;
  void PostProcessAfterData(QuicConnection* connection) override;
  void OnAckNeedsRetransmittableFrame(QuicConnection* connection) override;
  bool WillingAndAbleToWrite(QuicConnection* connection) const override;
  bool HasPendingHandshake(QuicConnection* connection) const override;
  bool HasOpenDynamicStreams(QuicConnection* connection) const override;
  bool OnAckFrame(QuicConnection* connection, const QuicAckFrame& frame, const QuicTime& arrival_time_of_packet) override;
  void OnNewSubflowFrame(QuicConnection* connection, const QuicNewSubflowFrame& frame) override;
  void OnSubflowCloseFrame(QuicConnection* connection, const QuicSubflowCloseFrame& frame) override;
  void OnRetransmission(const QuicTransmissionInfo& transmission_info) override;
  QuicFrames GetUpdatedAckFrames(QuicConnection* connection) override;

private:

  enum SubflowDirection {
    SUBFLOW_OUTGOING,
    SUBFLOW_INCOMING
  };

  void AckReceivedForSubflow(QuicConnection* connection, const QuicAckFrame& frame);

  // Creates a QuicConnection object for the specified subflow descriptor.
  void OpenConnection(QuicSubflowDescriptor descriptor, SubflowDirection direction);

  // Assigns a specific subflow id to a subflow.
  void AssignConnection(QuicSubflowDescriptor descriptor, QuicSubflowId subflowId, SubflowDirection direction);

  // Adds the QuicConnection object to the connections_ and subflow_descriptor_map_ map.
  void AddConnection(QuicSubflowDescriptor descriptor, QuicSubflowId subflowId, QuicConnection *connection);

  // Removes the connection from the connections_ and subflow_descriptor_map_ map.
  void RemoveConnection(QuicSubflowId subflowId);

  // Adds the connection to the unassigned_subflow_map_ map.
  void AddUnassignedConnection(QuicSubflowDescriptor descriptor, QuicConnection *connection);

  // Removes the connection from the unassigned_subflow_map_ map.
  void RemoveUnassignedConnection(QuicSubflowDescriptor descriptor);

  // If direction == SUBFLOW_INCOMING the peer initiated the closing and we
  // received a SUBFLOW_CLOSE frame for this subflow.
  // If direction == SUBFLOW_OUTGOING then we initiated the closing and start
  // sending SUBFLOW_CLOSE frame.
  void CloseConnection(QuicSubflowId subflowId, SubflowDirection direction);

  bool IsSubflowIdValid(QuicSubflowId subflowId, SubflowDirection direction, std::string* detailed_error);

  // Create packet writer for new connections
  QuicPacketWriter *GetPacketWriter(QuicSubflowDescriptor descriptor);

  void InitializeSubflowPacketHandler();

  QuicSubflowId GetNextOutgoingSubflowId();

  QuicConnection* GetConnection(QuicSubflowId subflowId) const;
  QuicConnection* GetConnection(const QuicSubflowDescriptor& subflowId) const;

  QuicConnectionManagerVisitorInterface *visitor_;

  // Whether a GoAway has been sent.
  bool goaway_sent_;

  // Whether a GoAway has been received.
  bool goaway_received_;

  // owns the QuicConnection objects
  std::map<QuicSubflowId, QuicConnection*> connections_;

  std::map<QuicSubflowDescriptor, QuicSubflowId> subflow_descriptor_map_;

  // Stores the connections with incoming handshake messages that did not yet
  // send a NEW_SUBFLOW frame (using a 0-RTT or 1-RTT packet).
  std::map<QuicSubflowDescriptor, QuicConnection*> unassigned_subflow_map_;

  // The ID to use for the next outgoing subflow.
  QuicSubflowId next_outgoing_subflow_id_;

  std::map<QuicSubflowDescriptor, QuicPacketWriter*> packet_writer_map_;

  // The subflow on which packets are sent.
  QuicSubflowId current_subflow_id_;

  // The subflow that will be used as the current subflow as soon as it is open.
  QuicSubflowId next_subflow_id_;

  MultipathSendAlgorithmInterface* multipath_send_algorithm_;

  DISALLOW_COPY_AND_ASSIGN(QuicConnectionManager);
};

} // namespace net

#endif /* NET_QUIC_CORE_NET_QUIC_CONNECTION_MANAGER_H_ */
