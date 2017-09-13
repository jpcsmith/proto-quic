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

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_MTCP_SEND_ALGORITHM_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_MTCP_SEND_ALGORITHM_H_

#include <list>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/congestion_control/multipath_send_algorithm_interface.h"

namespace net {

class QuicSubflowDescriptor;
struct QuicTransmissionInfo;

class QUIC_EXPORT_PRIVATE MtcpSendAlgorithm : public MultipathSendAlgorithmInterface {
public:
  MtcpSendAlgorithm(MultipathSchedulerInterface* scheduler);

  void OnCongestionEvent(
      const QuicSubflowDescriptor& descriptor, bool rtt_updated,
      QuicByteCount prior_in_flight, QuicTime event_time,
      const CongestionVector& acked_packets,
      const CongestionVector& lost_packets) override;

  bool OnPacketSent(
      const QuicSubflowDescriptor& descriptor, QuicTime sent_time,
      QuicByteCount bytes_in_flight, QuicPacketNumber packet_number,
      QuicByteCount bytes, HasRetransmittableData is_retransmittable) override;

  void OnRetransmissionTimeout(const QuicSubflowDescriptor& descriptor,
      bool packets_retransmitted) override;

private:
  void Ack(const QuicSubflowDescriptor& descriptor,QuicPacketLength length);
  void Loss(const QuicSubflowDescriptor& descriptor,QuicPacketLength length);
  QuicByteCount& w(const QuicSubflowDescriptor& descriptor);
  double rtt(const QuicSubflowDescriptor& descriptor);
  QuicByteCount wTotal();
  double a();

  DISALLOW_COPY_AND_ASSIGN(MtcpSendAlgorithm);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_MTCP_SEND_ALGORITHM_H_
