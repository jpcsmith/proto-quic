// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/olia_send_algorithm.h"

#include <math.h>

#include "net/quic/core/quic_constants.h"

namespace net {

int OliaSendAlgorithm::current_id_ = 0;

OliaSendAlgorithm::OliaSendAlgorithm(MultipathSchedulerInterface* scheduler)
    : MultipathSendAlgorithmInterface(scheduler) {

}
OliaSendAlgorithm::~OliaSendAlgorithm() {

}
void OliaSendAlgorithm::OnCongestionEvent(const QuicSubflowDescriptor& descriptor,
    bool rtt_updated, QuicByteCount prior_in_flight, QuicTime event_time,
    const CongestionVector& acked_packets, const CongestionVector& lost_packets) {
  for(std::pair<QuicPacketNumber, QuicPacketLength> p: acked_packets) {
    Ack(descriptor, p.second);
  }
  for(std::pair<QuicPacketNumber, QuicPacketLength> p: lost_packets) {
    Loss(descriptor, p.second);
  }
}

bool OliaSendAlgorithm::OnPacketSent(const QuicSubflowDescriptor& descriptor,
    QuicTime sent_time, QuicByteCount bytes_in_flight,
    QuicPacketNumber packet_number, QuicByteCount bytes,
    HasRetransmittableData is_retransmittable) {
  parameters_[descriptor].bytes_in_flight = bytes_in_flight+bytes;
  return true;
}

void OliaSendAlgorithm::OnRetransmissionTimeout(
    const QuicSubflowDescriptor& descriptor,
    bool packets_retransmitted) {

}

void OliaSendAlgorithm::AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
    RttStats* rttStats) {
  MultipathSendAlgorithmInterface::AddSubflow(subflowDescriptor, rttStats);
  olia_parameters_[subflowDescriptor] = OliaSubflowParameters();
}

void OliaSendAlgorithm::Ack(const QuicSubflowDescriptor& descriptor,QuicPacketLength length) {
  GetOliaParameters(descriptor).l2r += length;

  DeterminePaths();

  double alpha = 0;
  if(collected_paths_.find(descriptor) != collected_paths_.end()) {
    alpha = 1.0/(w(descriptor)*olia_parameters_.size()*collected_paths_.size());
  } else if(max_w_paths_.find(descriptor) != max_w_paths_.end() && !collected_paths_.empty()) {
    alpha = -1.0/(w(descriptor)*olia_parameters_.size()*max_w_paths_.size());
  }

  double sum = 0;
  for(std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p: olia_parameters_) {
    sum += ((double)w(p.first))/rtt(descriptor);
  }

  //TODO(cyrill) get maximum segment size
  double MSS_r = kDefaultTCPMSS;

  double left_term = w(descriptor)/
      (rtt(descriptor)*rtt(descriptor))/
      (sum*sum);

  double w_increase = (left_term+alpha)*MSS_r*GetOliaParameters(descriptor).l2r;

  QUIC_LOG(INFO) << "ACK(" << GetOliaParameters(descriptor).id << "," << length << ") w_r_new[" << (w(descriptor) + w_increase) <<
      "] = w_r[" << w(descriptor) << "]+(" << left_term << "+alpha[" << alpha <<
      "])*MSS_r[" << MSS_r << "]*bytes_acked[" << GetOliaParameters(descriptor).l2r << "] [" << w_increase << "]";


  w(descriptor) += w_increase;

// TODO(cyrill)
//  For each ACK on the path r:
//
//   - If r is in collected_paths, increase w_r by
//
//        w_r/rtt_r^2                          1
//    -------------------    +     -----------------------       (2)
//   (SUM (w_p/rtt_p))^2    w_r * number_of_paths * |collected_paths|
//
//   multiplied by MSS_r * bytes_acked.
//
//
//   - If r is in max_w_paths and if collected_paths is not empty,
//   increase w_r by
//
//         w_r/rtt_r^2                         1
//    --------------------    -     ------------------------     (3)
//    (SUM (w_r/rtt_r))^2     w_r * number_of_paths * |max_w_paths|
//
//   multiplied by MSS_r * bytes_acked.
//
//   - Otherwise, increase w_r by
//
//                          (w_r/rtt_r^2)
//                  ----------------------------------           (4)
//                         (SUM (w_r/rtt_r))^2
//
//   multiplied by MSS_r * bytes_acked.
}
void OliaSendAlgorithm::Loss(const QuicSubflowDescriptor& descriptor,QuicPacketLength length) {
  QUIC_LOG(INFO) << "LOSS(" << GetOliaParameters(descriptor).id << ") {" << GetOliaParameters(descriptor).l1r << "," << GetOliaParameters(descriptor).l2r << "} -> {" <<
      GetOliaParameters(descriptor).l2r << ",0}";

  GetOliaParameters(descriptor).l1r = GetOliaParameters(descriptor).l2r;
  GetOliaParameters(descriptor).l2r = 0;
}

QuicByteCount& OliaSendAlgorithm::w(const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].congestion_window;
}
double OliaSendAlgorithm::rtt(const QuicSubflowDescriptor& descriptor) {
  QuicTime::Delta srttDelta = parameters_[descriptor].rtt_stats->smoothed_rtt();
  double srtt = ((double)srttDelta.ToMicroseconds())/1000000;
  return srtt;
}
void OliaSendAlgorithm::DeterminePaths() {
  max_w_paths_.clear();
  QuicByteCount w_max = w(olia_parameters_.begin()->first);
  for(std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p: olia_parameters_) {
    if(w(p.first) > w_max) {
      w_max = w(p.first);
      max_w_paths_.clear();
      max_w_paths_.insert(p.first);
    } else if(w(p.first) == w_max) {
      max_w_paths_.insert(p.first);
    }
  }

  collected_paths_.clear();
  QuicSubflowDescriptor first = olia_parameters_.begin()->first;
  QuicByteCount usage_ratio = ((double)l(first))/rtt(first)/rtt(first);
  for(std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p: olia_parameters_) {
    double p_usage_ratio = ((double)l(p.first))/rtt(p.first)/rtt(p.first);
    if(p_usage_ratio > usage_ratio) {
      w_max = w(p.first);
      collected_paths_.clear();
      collected_paths_.insert(p.first);
    } else if(p_usage_ratio == usage_ratio) {
      collected_paths_.insert(p.first);
    }
  }
}
QuicByteCount OliaSendAlgorithm::l(const QuicSubflowDescriptor& descriptor) {
  OliaSubflowParameters p = GetOliaParameters(descriptor);
  return std::max(p.l1r,p.l2r);
}

} // namespace net
