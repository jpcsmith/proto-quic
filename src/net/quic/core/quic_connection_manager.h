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

  // QuicSubflowCreationAttemptDelegate
  //void OnSubflowCreationFailed(QuicSubflowId id) override;

  // QuicConnectionVisitorInterface
  void OnStreamFrame(const QuicSubflowId& subflowId, const QuicStreamFrame& frame) override;
  void OnWindowUpdateFrame(const QuicSubflowId& subflowId, const QuicWindowUpdateFrame& frame) override;
  void OnBlockedFrame(const QuicSubflowId& subflowId, const QuicBlockedFrame& frame) override;
  void OnRstStream(const QuicSubflowId& subflowId, const QuicRstStreamFrame& frame) override;
  void OnGoAway(const QuicSubflowId& subflowId, const QuicGoAwayFrame& frame) override;
  void OnConnectionClosed(const QuicSubflowId& subflowId,
                                  QuicErrorCode error,
                                  const std::string& error_details,
                                  ConnectionCloseSource source) override;
  void OnWriteBlocked(const QuicSubflowId& subflowId) override;
  void OnSuccessfulVersionNegotiation(const QuicSubflowId& subflowId, const QuicVersion& version) override;
  void OnCanWrite(const QuicSubflowId& subflowId) override;
  void OnCongestionWindowChange(const QuicSubflowId& subflowId, QuicTime now) override;
  void OnConnectionMigration(const QuicSubflowId& subflowId, PeerAddressChangeType type) override;
  void OnPathDegrading(const QuicSubflowId& subflowId) override;
  void PostProcessAfterData(const QuicSubflowId& subflowId) override;
  void OnAckNeedsRetransmittableFrame(const QuicSubflowId& subflowId) override;
  bool WillingAndAbleToWrite(const QuicSubflowId& subflowId) const override;
  bool HasPendingHandshake(const QuicSubflowId& subflowId) const override;
  bool HasOpenDynamicStreams(const QuicSubflowId& subflowId) const override;
  bool OnAckFrame(const QuicSubflowId& subflowId, const QuicAckFrame& frame, const QuicTime& arrival_time_of_packet) override;
  void OnSubflowCloseFrame(const QuicSubflowId& subflowId, const QuicSubflowCloseFrame& frame) override;
  void OnRetransmission(const QuicTransmissionInfo& transmission_info) override;
  QuicFrames GetUpdatedAckFrames(const QuicSubflowId& subflow_id) override;




  /*class QUIC_EXPORT_PRIVATE QuicSubflowCreationAttempt : public QuicAlarm::Delegate {
  public:
    const size_t kSubflowCreationTimeout = 1000;

    class QUIC_EXPORT_PRIVATE QuicSubflowCreationAttemptDelegate {
      virtual void OnSubflowCreationFailed(QuicSubflowId id) = 0;
    };

    QuicSubflowCreationAttempt(QuicSubflowDescriptor descriptor,
        QuicSubflowId subflow_id,
        QuicSubflowCreationAttemptDelegate *visitor,
        QuicClock *clock,
        QuicAlarmFactory *alarmFactory) :
          descriptor_(descriptor),
          subflow_id_(subflow_id),
          last_attempt_time_(clock->ApproximateNow()),
          n_attempts_(1),
          visitor_(visitor)
    {
      alarm_ = alarmFactory->CreateAlarm(this);
      alarm_->Set(last_attempt_time_+kSubflowCreationTimeout);
    }

    ~QuicSubflowCreationAttempt() {
      delete alarm_;
    }

    void OnAlarm() override {
      visitor_->OnSubflowCreationFailed(subflow_id_);
    }

  private:
    QuicSubflowDescriptor descriptor_;
    QuicSubflowId subflow_id_;
    QuicTime last_attempt_time_;
    size_t n_attempts_;
    QuicSubflowCreationAttemptDelegate *visitor_;
    QuicAlarm *alarm_;

    DISALLOW_COPY_AND_ASSIGN(QuicSubflowCreationAttempt);
  };*/

protected:

private:
  class QUIC_EXPORT_PRIVATE QuicSubflowPacketHandler : public QuicFramerVisitorInterface {
  public:
    QuicSubflowPacketHandler(
        const QuicVersionVector& supported_versions,
        QuicTime creation_time,
        Perspective perspective,
        QuicFramerCryptoContext *cc,
        bool owns_cc,
        QuicVersion version)
    : framer_(supported_versions, creation_time, perspective, cc, owns_cc, version) {
      framer_.set_visitor(this);
    }
    ~QuicSubflowPacketHandler() override {}

    // Processes a packet from a new subflow and checks whether there is exactly
    // one NEW_SUBFLOW frame.
    bool ProcessPacket(const QuicReceivedPacket& packet) {
      n_new_subflow_frames_ = 0;
      if(!framer_.ProcessPacket(packet)) {
        //TODO error handling
        return false;
      }

      return n_new_subflow_frames_ == 1;
    }
    QuicSubflowId GetLastSubflowId() {
      return subflow_id_;
    }

    void OnPacket() override;
    bool OnUnauthenticatedPublicHeader(
        const QuicPacketPublicHeader& header) override;
    bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override;
    void OnError(QuicFramer* framer) override;
    bool OnProtocolVersionMismatch(QuicVersion received_version) override; //TODO is this possible?
    void OnPublicResetPacket(const QuicPublicResetPacket& packet) override;
    void OnVersionNegotiationPacket(
        const QuicVersionNegotiationPacket& packet) override;
    void OnDecryptedPacket(EncryptionLevel level) override;
    bool OnPacketHeader(const QuicPacketHeader& header) override;
    bool OnStreamFrame(const QuicStreamFrame& frame) override;
    bool OnAckFrame(const QuicAckFrame& frame) override;
    bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override;
    bool OnPaddingFrame(const QuicPaddingFrame& frame) override;
    bool OnPingFrame(const QuicPingFrame& frame) override;
    bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override;
    bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override;
    bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override;
    bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override;
    bool OnBlockedFrame(const QuicBlockedFrame& frame) override;
    bool OnNewSubflowFrame(const QuicNewSubflowFrame& frame) override;
    bool OnSubflowCloseFrame(const QuicSubflowCloseFrame& frame) override;
    void OnPacketComplete() override;
  private:
    QuicFramer framer_;
    QuicSubflowId subflow_id_;
    int n_new_subflow_frames_;

    DISALLOW_COPY_AND_ASSIGN(QuicSubflowPacketHandler);
  };

  enum SubflowDirection {
    SUBFLOW_OUTGOING,
    SUBFLOW_INCOMING
  };
  void OpenConnection(QuicSubflowDescriptor descriptor, QuicSubflowId subflowId, SubflowDirection direction);
  void AddConnection(QuicSubflowDescriptor descriptor, QuicSubflowId subflowId, QuicConnection *connection);
  void CloseConnection(QuicSubflowId subflowId, SubflowDirection direction);
  void RemoveConnection(QuicSubflowId subflowId);

  // Create packet writer for new connections
  QuicPacketWriter *GetPacketWriter(QuicSubflowDescriptor descriptor);

  void InitializeSubflowPacketHandler();

  QuicSubflowId GetNextOutgoingSubflowId();
  bool IsValidIncomingSubflowId(QuicSubflowId id);
  bool IsValidOutgoingSubflowId(QuicSubflowId id);

  QuicConnectionManagerVisitorInterface *visitor_;

  // Whether a GoAway has been sent.
  bool goaway_sent_;

  // Whether a GoAway has been received.
  bool goaway_received_;

  // owns the QuicConnection objects
  std::map<QuicSubflowId, QuicConnection*> connections_;

  std::map<QuicSubflowDescriptor, QuicSubflowId> subflow_descriptor_map_;

  // A set of all subflows where a connection attempt was made.
  std::set<QuicSubflowDescriptor> buffered_outgoing_subflow_attempts_;
  // A set of buffered packets with their corresponding QuicSubflowDescriptor
  std::vector<std::pair<QuicSubflowDescriptor, std::unique_ptr<QuicReceivedPacket>> > buffered_incoming_subflow_attempts_;

  // The ID to use for the next outgoing subflow.
  QuicSubflowId next_outgoing_subflow_id_;

  // QuicFramer wrapper class for reading packets that do not belong to
  // a connection. (Packets on new subflows)
  QuicSubflowPacketHandler *packet_handler_;

  std::map<QuicSubflowDescriptor, QuicPacketWriter*> packet_writer_map_;

  // The subflow on which packets are sent.
  QuicSubflowId current_subflow_id_;

  // The subflow that will be used as the current subflow as soon as it is open.
  QuicSubflowId next_subflow_id_;

  /*std::map<QuicSubflowDescriptor, QuicSubflowCreationAttempt> subflow_attempt_map_;

  // helper classes
  QuicClock *clock_;
  QuicAlarmFactory *alarm_factory_;*/

  DISALLOW_COPY_AND_ASSIGN(QuicConnectionManager);
};

} // namespace net

#endif /* NET_QUIC_CORE_NET_QUIC_CONNECTION_MANAGER_H_ */
