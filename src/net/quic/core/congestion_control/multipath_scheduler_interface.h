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

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SCHEDULER_INTERFACE_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SCHEDULER_INTERFACE_H_

#include <list>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"

namespace net {

struct QuicTransmissionInfo;

class QUIC_EXPORT_PRIVATE MultipathSchedulerInterface {
public:
  MultipathSchedulerInterface();

  virtual ~MultipathSchedulerInterface();

  // Adds a subflow on which we can send and receive packets.
  virtual void AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
      const RttStats* rttStats);

  // Returns the subflows sorted by preference for sending a packet.
  virtual std::list<QuicSubflowDescriptor> GetSubflowPriority() = 0;
  // Is called after GetSubflowPriority() to inform the scheduler which subflow
  // was used
  virtual void UsedSubflow(const QuicSubflowDescriptor& descriptor) = 0;

  // Returns the additional subflows for which we should send ack frames on the subflow described by
  // packetSubflowDescriptor.
  virtual std::list<QuicSubflowDescriptor> GetAckFramePriority(
      const QuicSubflowDescriptor& packetSubflowDescriptor) = 0;
  // Is called after GetAckFramePriority() by the connection manager to inform the send algorithm
  // which ack frames were sent.
  virtual void AckFramesAppended(
      std::list<QuicSubflowDescriptor> descriptors) = 0;

  // Notification if an ack frame of a subflow was updated. Used for adding the last
  // modified ack first.
  virtual void OnAckFrameUpdated(const QuicSubflowDescriptor& descriptor) = 0;

private:
  std::map<const QuicSubflowDescriptor, const RttStats*> parameters_;


  DISALLOW_COPY_AND_ASSIGN(MultipathSchedulerInterface);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SCHEDULER_INTERFACE_H_
