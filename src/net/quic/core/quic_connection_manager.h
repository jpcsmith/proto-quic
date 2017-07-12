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

class QUIC_EXPORT_PRIVATE QuicConnectionManagerVisitorInterface : public QuicConnectionVisitorInterface {
};

class QUIC_EXPORT_PRIVATE QuicConnectionManager: public QuicConnectionVisitorInterface {
public:
  QuicConnectionManager(QuicConnection *connection);
  ~QuicConnectionManager() override;

  void set_visitor(QuicConnectionManagerVisitorInterface* visitor) {
    visitor_ = visitor;
  }

  QuicConnection *InitialConnection() const {
    //QUIC_DLOG(INFO) << "connections_ (" << connections_.size() << "): ";
    //for(auto elem : connections_)
    //{
    //  QUIC_DLOG(INFO) << elem.first << ": " << elem.second << "\n";
    //}
    return connections_.at(kInitialSubflowId);
  }

  void set_current_subflow_id(QuicSubflowId id) { current_subflow_id_ = id; }

  QuicConnection *connection() const {
    return connections_.find(current_subflow_id_)->second;
    //return connections_[current_subflow_id_];
  }

  QuicConnection *AnyConnection() const {
    QUIC_BUG_IF(connections_.size()==0) << "There are no connections";
    return connections_.begin()->second;
  }

  void TryAddingSubflow(QuicSubflowDescriptor descriptor);
  void AddPacketWriter(QuicSubflowDescriptor descriptor, QuicPacketWriter *writer);
  void CloseSubflow(QuicSubflowId id);
  void ProcessUdpPacket(const QuicSocketAddress& self_address,
                                     const QuicSocketAddress& peer_address,
                                     const QuicReceivedPacket& packet);

  // QuicSubflowCreationAttemptDelegate
  //void OnSubflowCreationFailed(QuicSubflowId id) override;

  // QuicConnectionVisitorInterface
  void OnStreamFrame(const QuicStreamFrame& frame) override;
  void OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override;
  void OnBlockedFrame(const QuicBlockedFrame& frame) override;
  void OnRstStream(const QuicRstStreamFrame& frame) override;
  void OnGoAway(const QuicGoAwayFrame& frame) override;
  void OnConnectionClosed(QuicErrorCode error,
      const std::string& error_details, ConnectionCloseSource source) override;
  void OnWriteBlocked() override;
  void OnSuccessfulVersionNegotiation(const QuicVersion& version) override;
  void OnCanWrite() override;
  void OnCongestionWindowChange(QuicTime now) override;
  void OnConnectionMigration(PeerAddressChangeType type) override;
  void OnPathDegrading() override;
  void PostProcessAfterData() override;
  void OnAckNeedsRetransmittableFrame() override;
  bool WillingAndAbleToWrite() const override;
  bool HasPendingHandshake() const override;
  bool HasOpenDynamicStreams() const override;
  void OnAckFrame(const QuicAckFrame& frame) override;
  void OnHandshakeComplete() override;
  void OnSubflowCloseFrame(const QuicSubflowCloseFrame& frame) override;




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

  QuicSubflowId current_subflow_id_;

  /*std::map<QuicSubflowDescriptor, QuicSubflowCreationAttempt> subflow_attempt_map_;

  // helper classes
  QuicClock *clock_;
  QuicAlarmFactory *alarm_factory_;*/

  DISALLOW_COPY_AND_ASSIGN(QuicConnectionManager);
};

} // namespace net

#endif /* NET_QUIC_CORE_NET_QUIC_CONNECTION_MANAGER_H_ */
