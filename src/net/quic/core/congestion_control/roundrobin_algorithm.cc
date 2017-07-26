// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/roundrobin_algorithm.h"

namespace net {

RoundRobinAlgorithm::~RoundRobinAlgorithm() {
}

void RoundRobinAlgorithm::AddSubflow(QuicSubflowId subflowId) {
}

QuicSubflowId RoundRobinAlgorithm::GetNextStreamFrameSubflow(
    QuicStreamId streamId, size_t length, QuicSubflowId hint, SendReason reason) {
}
QuicSubflowId RoundRobinAlgorithm::GetNextControlFrameSubflow(
    const QuicFrame& frame, QuicSubflowId hint) {
}

std::list<QuicSubflowId> RoundRobinAlgorithm::AppendAckFrames(
    QuicSubflowId packetSubflowId) {
}
void RoundRobinAlgorithm::AckFramesAppended(
    const std::list<QuicSubflowId>& ackFrameSubflowIds) {
}

void RoundRobinAlgorithm::OnAckFrameUpdated(const QuicAckFrame& frame) {
}

}
