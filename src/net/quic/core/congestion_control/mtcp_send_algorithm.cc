// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/mtcp_send_algorithm.h"

#include <math.h>

namespace net {

MtcpSendAlgorithm::MtcpSendAlgorithm(MultipathSchedulerInterface* scheduler)
    : MultipathSendAlgorithmInterface(scheduler) {

}
void MtcpSendAlgorithm::OnCongestionEvent(const QuicSubflowDescriptor& descriptor,
    bool rtt_updated, QuicByteCount prior_in_flight, QuicTime event_time,
    const CongestionVector& acked_packets, const CongestionVector& lost_packets) {
  for(std::pair<QuicPacketNumber, QuicPacketLength> p: acked_packets) {
    Ack(descriptor, p.second);
  }
  for(std::pair<QuicPacketNumber, QuicPacketLength> p: lost_packets) {
    Loss(descriptor, p.second);
  }
}

bool MtcpSendAlgorithm::OnPacketSent(const QuicSubflowDescriptor& descriptor,
    QuicTime sent_time, QuicByteCount bytes_in_flight,
    QuicPacketNumber packet_number, QuicByteCount bytes,
    HasRetransmittableData is_retransmittable) {
  parameters_[descriptor].bytes_in_flight = bytes_in_flight+bytes;
  return true;
}

void MtcpSendAlgorithm::OnRetransmissionTimeout(
    const QuicSubflowDescriptor& descriptor,
    bool packets_retransmitted) {

}

void MtcpSendAlgorithm::Ack(const QuicSubflowDescriptor& descriptor,QuicPacketLength length) {
  w(descriptor) += length*std::min(a()/wTotal(),1.0/w(descriptor));
}
void MtcpSendAlgorithm::Loss(const QuicSubflowDescriptor& descriptor,QuicPacketLength length) {
  w(descriptor) = std::max(w(descriptor)/2,kInitialCongestionWindow);
}

QuicByteCount& MtcpSendAlgorithm::w(const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].congestion_window;
}
double MtcpSendAlgorithm::rtt(const QuicSubflowDescriptor& descriptor) {
  QuicTime::Delta srttDelta = parameters_[descriptor].rtt_stats->smoothed_rtt();
  double srtt = ((double)srttDelta.ToMicroseconds())/1000000;
  return srtt;
}
QuicByteCount MtcpSendAlgorithm::wTotal() {
  QuicByteCount wt = 0;
  for(std::pair<QuicSubflowDescriptor,SubflowParameters> p: parameters_) {
    wt += w(p.first);
  }
  return wt;
}
double MtcpSendAlgorithm::a() {
  // numerator = max(w(r)/RTT(r)^2)
  // denominator = sum(w(r)/RTT(r))^2
  // a = wTotal*(numerator/denominator)
  double numerator = 0, denominator = 0;
  for(std::pair<QuicSubflowDescriptor,SubflowParameters> p: parameters_) {
    double srtt = rtt(p.first);
    double pNumerator = ((double)w(p.first))/srtt/srtt;

    if(pNumerator > numerator) {
      numerator = pNumerator;
    }
    denominator += ((double)w(p.first))/srtt;
  }
  denominator *= denominator;
  return ((double)wTotal())*numerator/denominator;
}

} // namespace net
