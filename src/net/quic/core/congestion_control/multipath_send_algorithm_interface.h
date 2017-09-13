// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The pure virtual class for send side congestion control algorithm in a
// multipathing environment.
//
// This interface only operates on subflows where the subflow id is known
// to both endpoints. This means that each subflow has an assigned
// QuicSubflowId and ack frames of this subflow can be interpreted.

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SEND_ALGORITHM_INTERFACE_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SEND_ALGORITHM_INTERFACE_H_

#include <list>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/congestion_control/multipath_scheduler_interface.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"
#include "net/quic/core/quic_config.h"

namespace net {

class CachedNetworkParameters;
struct QuicTransmissionInfo;

class QUIC_EXPORT_PRIVATE MultipathSendAlgorithmInterface {
public:
  // A sorted vector of packets.
  typedef std::vector<std::pair<QuicPacketNumber, QuicPacketLength>> CongestionVector;
  const QuicPacketLength max_frame_length = 1; //TODO(cyrill) get actual max frame length

  enum SendReason {
    ENCRYPTED_TRANSMISSION, UNENCRYPTED_TRANSMISSION
  };

  MultipathSendAlgorithmInterface(MultipathSchedulerInterface* scheduler);

  virtual ~MultipathSendAlgorithmInterface();

  virtual void AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
      RttStats* rttStats);

  virtual void SetFromConfig(const QuicConfig& config, Perspective perspective);

  // Sets the number of connections to emulate when doing congestion control,
  // particularly for congestion avoidance.  Can be set any time.
  virtual void SetNumEmulatedConnections(int num_connections);

  // Indicates an update to the congestion state, caused either by an incoming
  // ack or loss event timeout.  |rtt_updated| indicates whether a new
  // latest_rtt sample has been taken, |prior_in_flight| the bytes in flight
  // prior to the congestion event.  |acked_packets| and |lost_packets| are any
  // packets considered acked or lost as a result of the congestion event.
  virtual void OnCongestionEvent(const QuicSubflowDescriptor& descriptor,
      bool rtt_updated, QuicByteCount prior_in_flight, QuicTime event_time,
      const CongestionVector& acked_packets,
      const CongestionVector& lost_packets) = 0;

  // Inform that we sent |bytes| to the wire, and if the packet is
  // retransmittable. Returns true if the packet should be tracked by the
  // congestion manager and included in bytes_in_flight, false otherwise.
  // |bytes_in_flight| is the number of bytes in flight before the packet was
  // sent.
  // Note: this function must be called for every packet sent to the wire.
  virtual bool OnPacketSent(const QuicSubflowDescriptor& descriptor,
      QuicTime sent_time, QuicByteCount bytes_in_flight,
      QuicPacketNumber packet_number, QuicByteCount bytes,
      HasRetransmittableData is_retransmittable) = 0;

  // Called when the retransmission timeout fires.  Neither OnPacketAbandoned
  // nor OnPacketLost will be called for these packets.
  virtual void OnRetransmissionTimeout(const QuicSubflowDescriptor& descriptor,
      bool packets_retransmitted) = 0;

  // Called when connection migrates and cwnd needs to be reset.
  // Not used in multipath quic.
  virtual void OnConnectionMigration();

  // Calculate the time until we can send the next packet.
  virtual QuicTime::Delta TimeUntilSend(const QuicSubflowDescriptor& descriptor,
      QuicTime now, QuicByteCount bytes_in_flight);

  // The pacing rate of the send algorithm.  May be zero if the rate is unknown.
  virtual QuicBandwidth PacingRate(QuicByteCount bytes_in_flight) const;

  // What's the current estimated bandwidth in bytes per second.
  // Returns 0 when it does not have an estimate.
  virtual QuicBandwidth BandwidthEstimate(
      const QuicSubflowDescriptor& descriptor) const;

  // Returns the size of the current total congestion window in bytes.  Note, this is
  // not the *available* window.  Some send algorithms may not use a congestion
  // window and will return 0.
  virtual QuicByteCount GetCongestionWindow(
      const QuicSubflowDescriptor& descriptor) const;

  // Whether the send algorithm is currently in slow start.  When true, the
  // BandwidthEstimate is expected to be too low.
  virtual bool InSlowStart(const QuicSubflowDescriptor& descriptor) const;

  // Whether the send algorithm is currently in recovery.
  virtual bool InRecovery(const QuicSubflowDescriptor& descriptor) const;

  // Returns the size of the slow start congestion window in bytes,
  // aka ssthresh.  Some send algorithms do not define a slow start
  // threshold and will return 0.
  virtual QuicByteCount GetSlowStartThreshold(
      const QuicSubflowDescriptor& descriptor) const;

  virtual CongestionControlType GetCongestionControlType() const;

  // Called by the Session when we get a bandwidth estimate from the client.
  // Uses the max bandwidth in the params if |max_bandwidth_resumption| is true.
  virtual void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption);

  // Retrieves debugging information about the current state of the
  // send algorithm.
  virtual std::string GetDebugState() const;

  // Called when the connection has no outstanding data to send. Specifically,
  // this means that none of the data streams are write-blocked, there are no
  // packets in the connection queue, and there are no pending retransmissins,
  // i.e. the sender cannot send anything for reasons other than being blocked
  // by congestion controller. This includes cases when the connection is
  // blocked by the flow controller.
  //
  // The fact that this method is called does not necessarily imply that the
  // connection would not be blocked by the congestion control if it actually
  // tried to send data. If the congestion control algorithm needs to exclude
  // such cases, it should use the internal state it uses for congestion control
  // for that.
  virtual void OnApplicationLimited(QuicByteCount bytes_in_flight);

  // The following functions return the descriptor of the subflow where a frame should
  // be sent on. If hint.IsInitialized() returns true it describes the subflow on which
  // we received the stream frame (used for returning crypto handshakes on the same subflow).
  // reason is used to determine if the frame is a crypto handshake message.
  virtual QuicSubflowDescriptor GetNextStreamFrameSubflow(QuicStreamId streamId,
      size_t length, const QuicSubflowDescriptor& hint, SendReason reason);
  // If hint.IsInitialized() returns true it describes the subflow which initiated sending
  // the frame.
  virtual QuicSubflowDescriptor GetNextControlFrameSubflow(
      const QuicFrame& frame, const QuicSubflowDescriptor& hint);
  // Choose the subflow on which this packet should be retransmitted.
  virtual QuicSubflowDescriptor GetNextRetransmissionSubflow(
      const QuicTransmissionInfo& transmission_info,
      const QuicSubflowDescriptor& hint);

  // Returns the additional subflows for which we should send ack frames on the subflow described by
  // packetSubflowDescriptor.
  virtual std::list<QuicSubflowDescriptor> AppendAckFrames(
      const QuicSubflowDescriptor& packetSubflowDescriptor);
  // Is called after AppendAckFrames() by the connection manager to inform the send algorithm
  // which ack frames were sent.
  virtual void AckFramesAppended(
      const std::list<QuicSubflowDescriptor>& ackFrameSubflowDescriptors);

  // Notification if an ack frame of a subflow was updated. Used for adding the last
  // modified ack first.
  virtual void OnAckFrameUpdated(
      const QuicSubflowDescriptor& subflowDescriptor);

  void InitialEncryptionEstablished(const QuicSubflowDescriptor& descriptor);
  virtual void ForwardSecureEncryptionEstablished(
      const QuicSubflowDescriptor& descriptor);
  EncryptionLevel GetEncryptionLevel(const QuicSubflowDescriptor& descriptor);

protected:
  QuicSubflowDescriptor uninitialized_subflow_descriptor_;

  virtual bool CanSendOnSubflow(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength length, bool needsForwardSecureEncryption);
  virtual bool FitsCongestionWindow(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength length);
  virtual bool HasForwardSecureSubflow();
  virtual bool IsForwardSecure(const QuicSubflowDescriptor& descriptor);
  virtual bool IsInitialSecure(const QuicSubflowDescriptor& descriptor);
  virtual void SentOnSubflow(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength length);
  // Returns the next subflow provided by the scheduler which has enough space in its
  // congestion window to send a packet of size |length|. If there is no such subflow,
  // it returns the next subflow with sufficient encryption even if there is not enough
  // space in the congestion window.
  //
  // If |allowInitialEncryption| is false, we only allow subflows with forward secure encryption.
  // If it is true, we allow subflows with initial or forward secure encryption.
  QuicSubflowDescriptor GetNextSubflow(QuicPacketLength length,
      bool allowInitialEncryption);
  virtual QuicSubflowDescriptor GetNextPossibleSubflow(QuicPacketLength length);
  virtual QuicSubflowDescriptor GetNextForwardSecureSubflow();

  enum SubflowCongestionState {
    SUBFLOW_CONGESTION_SLOWSTART, SUBFLOW_CONGESTION_RECOVERY
  };

  struct SubflowParameters {
    SubflowParameters() {
    }
    SubflowParameters(RttStats* rttStats)
        : rtt_stats(rttStats), congestion_window(kInitialCongestionWindow*kDefaultTCPMSS), bytes_in_flight(
            0), congestion_state(SUBFLOW_CONGESTION_SLOWSTART), forward_secure_encryption_established(
            false), encryption_level(ENCRYPTION_NONE), in_slow_start(false) {
    }
    RttStats* rtt_stats;
    QuicByteCount congestion_window;
    QuicByteCount bytes_in_flight;
    SubflowCongestionState congestion_state;
    bool forward_secure_encryption_established;
    EncryptionLevel encryption_level;
    bool in_slow_start;
  };

  std::map<QuicSubflowDescriptor, SubflowParameters> parameters_;

  bool TracksDescriptor(const QuicSubflowDescriptor& descriptor) const {
    return parameters_.find(descriptor) != parameters_.end();
  }
  const SubflowParameters& GetParameters(const QuicSubflowDescriptor& descriptor) const {
    DCHECK(TracksDescriptor(descriptor));
    return parameters_.at(descriptor);
  }

private:
  std::unique_ptr<MultipathSchedulerInterface> scheduler_;

  DISALLOW_COPY_AND_ASSIGN(MultipathSendAlgorithmInterface);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SEND_ALGORITHM_INTERFACE_H_
