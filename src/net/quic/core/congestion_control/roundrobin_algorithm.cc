// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/roundrobin_algorithm.h"

namespace net {

RoundRobinAlgorithm::RoundRobinAlgorithm() :
  subflow_descriptors_(std::vector<QuicSubflowDescriptor>()),
  ack_frame_descriptors_(std::vector<QuicSubflowDescriptor>()),
  current_index_(0) {

}

RoundRobinAlgorithm::~RoundRobinAlgorithm() {

}

void RoundRobinAlgorithm::AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
    const RttStats* rttStats) {
  DCHECK(std::find(subflow_descriptors_.begin(),subflow_descriptors_.end(),subflowDescriptor) == subflow_descriptors_.end());
  MultipathSchedulerInterface::AddSubflow(subflowDescriptor, rttStats);
  subflow_descriptors_.push_back(subflowDescriptor);
}

std::list<QuicSubflowDescriptor> RoundRobinAlgorithm::GetSubflowPriority() {
  size_t index = AdvanceIndex();
  std::list<QuicSubflowDescriptor> p(subflow_descriptors_.begin()+index, subflow_descriptors_.end());
  p.insert(p.end(),subflow_descriptors_.begin(),subflow_descriptors_.begin()+index);
  return p;
}
void RoundRobinAlgorithm::UsedSubflow(const QuicSubflowDescriptor& descriptor) {
  // Change current index to the next index.
  size_t index = 1;
  for(QuicSubflowDescriptor d: subflow_descriptors_) {
    if(d==descriptor) {
      current_index_ = index;
    }
    ++index;
  }
}

std::list<QuicSubflowDescriptor> RoundRobinAlgorithm::GetAckFramePriority(
    const QuicSubflowDescriptor& packetSubflowDescriptor) {
  return std::list<QuicSubflowDescriptor>(
        ack_frame_descriptors_.begin(),ack_frame_descriptors_.end());
}
void RoundRobinAlgorithm::AckFramesAppended(
    std::list<QuicSubflowDescriptor> descriptors) {
  for(auto it: descriptors) {
    auto pos = std::find(ack_frame_descriptors_.begin(),ack_frame_descriptors_.end(), it);
    if(pos != ack_frame_descriptors_.end()) {
      ack_frame_descriptors_.erase(pos);
    }
  }
}
void RoundRobinAlgorithm::OnAckFrameUpdated(const QuicSubflowDescriptor& descriptor) {
  ack_frame_descriptors_.push_back(descriptor);
}

size_t RoundRobinAlgorithm::AdvanceIndex() {
  return (current_index_++)%subflow_descriptors_.size();
}
void RoundRobinAlgorithm::SetIndex(size_t index) {
  current_index_ = index;
}

}
