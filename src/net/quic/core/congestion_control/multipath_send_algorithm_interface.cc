// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "net/quic/core/congestion_control/multipath_send_algorithm_interface.h"
#include "net/quic/core/quic_transmission_info.h"

namespace net {

MultipathSendAlgorithmInterface::MultipathSendAlgorithmInterface(
    MultipathSchedulerInterface* scheduler)
    : scheduler_(scheduler) {

}

MultipathSendAlgorithmInterface::~MultipathSendAlgorithmInterface() {
}

void MultipathSendAlgorithmInterface::AddSubflow(
    const QuicSubflowDescriptor& subflowDescriptor, RttStats* rttStats) {
  scheduler_->AddSubflow(subflowDescriptor, rttStats);
  SubflowParameters sp(rttStats);
  parameters_[subflowDescriptor] = sp;
}

void MultipathSendAlgorithmInterface::SetFromConfig(const QuicConfig& config,
    Perspective perspective) {

}

void MultipathSendAlgorithmInterface::SetNumEmulatedConnections(
    int num_connections) {

}

void MultipathSendAlgorithmInterface::MultipathSendAlgorithmInterface::OnConnectionMigration() {

}

QuicTime::Delta MultipathSendAlgorithmInterface::TimeUntilSend(
    const QuicSubflowDescriptor& descriptor, QuicTime now,
    QuicByteCount bytes_in_flight) {
  if (bytes_in_flight < parameters_[descriptor].congestion_window) {
    return QuicTime::Delta::Zero();
  } else {
    QUIC_LOG(INFO) << bytes_in_flight << " >= " << parameters_[descriptor].congestion_window;
    return QuicTime::Delta::Infinite();
  }
}

QuicBandwidth MultipathSendAlgorithmInterface::PacingRate(
    QuicByteCount bytes_in_flight) const {
  //TODO(cyrill)
  return QuicBandwidth::FromBytesPerSecond(0);
}

QuicBandwidth MultipathSendAlgorithmInterface::BandwidthEstimate(
    const QuicSubflowDescriptor& descriptor) const {
  //TODO(cyrill)
  return QuicBandwidth::FromBytesPerSecond(0);
}

QuicByteCount MultipathSendAlgorithmInterface::GetCongestionWindow(
    const QuicSubflowDescriptor& descriptor) const {
  if (!descriptor.IsInitialized()) {
    return std::accumulate(parameters_.begin(), parameters_.end(), 0,
        [](size_t val, std::pair<const QuicSubflowDescriptor, SubflowParameters> it) {
          return it.second.congestion_window + val;
        });
  } else {
    DCHECK(parameters_.find(descriptor) != parameters_.end());
    return parameters_.at(descriptor).congestion_window;
  }
}

bool MultipathSendAlgorithmInterface::InSlowStart(
    const QuicSubflowDescriptor& descriptor) const {
  DCHECK(TracksDescriptor(descriptor));
  return GetParameters(descriptor).in_slow_start;
}

bool MultipathSendAlgorithmInterface::InRecovery(
    const QuicSubflowDescriptor& descriptor) const {
  DCHECK(TracksDescriptor(descriptor));
  return !GetParameters(descriptor).in_slow_start;
}

QuicByteCount MultipathSendAlgorithmInterface::GetSlowStartThreshold(
    const QuicSubflowDescriptor& descriptor) const {
  return 0;
}

CongestionControlType MultipathSendAlgorithmInterface::GetCongestionControlType() const {
  return CongestionControlType::kCubic;
}

void MultipathSendAlgorithmInterface::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {

}

std::string MultipathSendAlgorithmInterface::GetDebugState() const {
  return "";
}

void MultipathSendAlgorithmInterface::OnApplicationLimited(
    QuicByteCount bytes_in_flight) {

}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextStreamFrameSubflow(
    QuicStreamId streamId, size_t length, const QuicSubflowDescriptor& hint,
    SendReason reason) {
  // Always send unencrypted packets on the subflow they belong.
  if (reason == UNENCRYPTED_TRANSMISSION) {
    DCHECK(hint.IsInitialized());
    return hint;
  }
  QuicSubflowDescriptor descriptor = GetNextSubflow(length, !HasForwardSecureSubflow());
  SentOnSubflow(descriptor, length);
  return descriptor;
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextControlFrameSubflow(
    const QuicFrame& frame, const QuicSubflowDescriptor& hint) {
  QuicSubflowDescriptor descriptor;
  // Always send control frames on the subflow that issued them.
  if (hint.IsInitialized()) {
    descriptor = hint;
  } else {
    descriptor = GetNextSubflow(max_frame_length, !HasForwardSecureSubflow());
  }

  SentOnSubflow(descriptor, max_frame_length);
  return descriptor;
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextRetransmissionSubflow(
    const QuicTransmissionInfo& transmission_info,
    const QuicSubflowDescriptor& hint) {
  // Always retransmit unencrypted and 0-RTT packets on the same subflow
  if (transmission_info.encryption_level != ENCRYPTION_FORWARD_SECURE) {
    DCHECK(hint.IsInitialized());
    return hint;
  }
  QuicSubflowDescriptor descriptor = GetNextSubflow(transmission_info.bytes_sent, !HasForwardSecureSubflow());
  SentOnSubflow(descriptor, transmission_info.bytes_sent);
  return descriptor;
}

std::list<QuicSubflowDescriptor> MultipathSendAlgorithmInterface::AppendAckFrames(
    const QuicSubflowDescriptor& packetSubflowDescriptor) {
  return scheduler_->GetAckFramePriority(packetSubflowDescriptor);
}
void MultipathSendAlgorithmInterface::AckFramesAppended(
    const std::list<QuicSubflowDescriptor>& ackFrameSubflowDescriptors) {
  scheduler_->AckFramesAppended(ackFrameSubflowDescriptors);
}

void MultipathSendAlgorithmInterface::OnAckFrameUpdated(
    const QuicSubflowDescriptor& subflowDescriptor) {
  scheduler_->OnAckFrameUpdated(subflowDescriptor);
}

void MultipathSendAlgorithmInterface::InitialEncryptionEstablished(
    const QuicSubflowDescriptor& descriptor) {
  parameters_[descriptor].encryption_level = ENCRYPTION_INITIAL;
}

void MultipathSendAlgorithmInterface::ForwardSecureEncryptionEstablished(
    const QuicSubflowDescriptor& descriptor) {
  parameters_[descriptor].forward_secure_encryption_established = true;
  parameters_[descriptor].encryption_level = ENCRYPTION_FORWARD_SECURE;
}

EncryptionLevel MultipathSendAlgorithmInterface::GetEncryptionLevel(const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].encryption_level;
}

bool MultipathSendAlgorithmInterface::CanSendOnSubflow(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length,
    bool needsForwardSecureEncryption) {
  return parameters_[descriptor].bytes_in_flight + length
      <= parameters_[descriptor].congestion_window
      && (!needsForwardSecureEncryption
          || parameters_[descriptor].forward_secure_encryption_established);
}
bool MultipathSendAlgorithmInterface::HasForwardSecureSubflow() {
  return std::any_of(parameters_.begin(), parameters_.end(),
      [](std::pair<const QuicSubflowDescriptor, SubflowParameters> p) {return p.second.encryption_level == ENCRYPTION_FORWARD_SECURE;});
}
bool MultipathSendAlgorithmInterface::FitsCongestionWindow(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length) {
  //TODO(cyrill) remove true
  return true || parameters_[descriptor].bytes_in_flight + length
      <= parameters_[descriptor].congestion_window;
}
bool MultipathSendAlgorithmInterface::IsForwardSecure(
    const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].encryption_level == ENCRYPTION_FORWARD_SECURE;
}
bool MultipathSendAlgorithmInterface::IsInitialSecure(
    const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].encryption_level == ENCRYPTION_INITIAL;
}
void MultipathSendAlgorithmInterface::SentOnSubflow(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length) {
  scheduler_->UsedSubflow(descriptor);
}
QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextSubflow(
    QuicPacketLength length, bool allowInitialEncryption) {
  QuicSubflowDescriptor fwFitting, fw, initialFitting, initial;
  int k = 0;
  for (const QuicSubflowDescriptor& descriptor : scheduler_->GetSubflowPriority()) {
    QUIC_LOG(INFO) << "desc(" << k++ << "): " << descriptor.ToString() << ": fit = " << FitsCongestionWindow(descriptor, length) << " fwsec = " << IsForwardSecure(descriptor) << " initsec = " << IsInitialSecure(descriptor);

    if (!fwFitting.IsInitialized() && FitsCongestionWindow(descriptor, length)
        && IsForwardSecure(descriptor)) {
      fwFitting = descriptor;
    }
    if (!fw.IsInitialized() && IsForwardSecure(descriptor)) {
      fw = descriptor;
    }
    if (!initialFitting.IsInitialized()
        && FitsCongestionWindow(descriptor, length)
        && IsInitialSecure(descriptor)) {
      initialFitting = descriptor;
    }
    if (!initial.IsInitialized() && IsInitialSecure(descriptor)) {
      fwFitting = descriptor;
    }
  }

  if (fwFitting.IsInitialized()) {
    return fwFitting;
  }
  if (allowInitialEncryption && initialFitting.IsInitialized()) {
    return initialFitting;
  }
  if (fw.IsInitialized()) {
    return fw;
  }
  if (allowInitialEncryption && initial.IsInitialized()) {
    return initialFitting;
  }
  // should never reach here
  DCHECK(false);
  return QuicSubflowDescriptor();
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextPossibleSubflow(
    QuicPacketLength length) {
  std::list<QuicSubflowDescriptor> subflowPriority =
      scheduler_->GetSubflowPriority();
  for (const QuicSubflowDescriptor& descriptor : subflowPriority) {
    if (CanSendOnSubflow(descriptor, length, true)) {
      return descriptor;
    }
  }
  return uninitialized_subflow_descriptor_;
}
QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextForwardSecureSubflow() {
  std::list<QuicSubflowDescriptor> subflowPriority =
      scheduler_->GetSubflowPriority();
  for (const QuicSubflowDescriptor& descriptor : subflowPriority) {
    QUIC_LOG(INFO)
        << descriptor.ToString() << " fw = "
            << parameters_[descriptor].forward_secure_encryption_established;
    if (parameters_[descriptor].forward_secure_encryption_established) {
      return descriptor;
    }
  }
  return uninitialized_subflow_descriptor_;
}

} // namespace net
