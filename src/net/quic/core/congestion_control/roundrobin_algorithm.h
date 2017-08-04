// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A simple scheduling algorithm that assigns the packets to each subflow in
// a round-robin fashion.

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_ROUND_ROBIN_ALGORITHM_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_ROUND_ROBIN_ALGORITHM_H_

#include <list>

#include "net/quic/core/congestion_control/multipath_scheduler_interface.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"

namespace net {

class QUIC_EXPORT_PRIVATE RoundRobinAlgorithm: public MultipathSchedulerInterface {
public:
  RoundRobinAlgorithm();

  ~RoundRobinAlgorithm() override;

  void AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
      const RttStats* rttStats) override;

  std::list<QuicSubflowDescriptor> GetSubflowPriority() override;
  void UsedSubflow(const QuicSubflowDescriptor& descriptor) override;

  std::list<QuicSubflowDescriptor> GetAckFramePriority(
      const QuicSubflowDescriptor& packetSubflowDescriptor) override;
  void AckFramesAppended(
      std::list<QuicSubflowDescriptor> descriptors) override;

  void OnAckFrameUpdated(const QuicSubflowDescriptor& descriptor) override;

private:
  size_t AdvanceIndex();
  void SetIndex(size_t index);

  std::vector<QuicSubflowDescriptor> subflow_descriptors_;

  // A list of updated ack frames that should be sent. Sorted by the
  // update time (lower entries are earlier updated ack frames).
  std::vector<QuicSubflowDescriptor> ack_frame_descriptors_;

  size_t current_index_;

  DISALLOW_COPY_AND_ASSIGN(RoundRobinAlgorithm);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_ROUND_ROBIN_H_
