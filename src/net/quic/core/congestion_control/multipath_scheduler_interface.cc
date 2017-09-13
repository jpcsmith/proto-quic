// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/multipath_scheduler_interface.h"

namespace net {

MultipathSchedulerInterface::MultipathSchedulerInterface() {

}

MultipathSchedulerInterface::~MultipathSchedulerInterface() {}

void MultipathSchedulerInterface::AddSubflow(const QuicSubflowDescriptor& subflowDescriptor, const RttStats* rttStats) {
  parameters_[subflowDescriptor] = rttStats;
}

}  // namespace net
