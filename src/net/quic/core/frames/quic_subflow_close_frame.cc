// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/frames/quic_subflow_close_frame.h"

namespace net {

QuicSubflowCloseFrame::QuicSubflowCloseFrame(QuicSubflowId subflow_id)
    : subflow_id(subflow_id) {}

std::ostream& operator<<(std::ostream& os,
                         const QuicSubflowCloseFrame& new_subflow_frame) {
  os << "{ subflow_id: " << new_subflow_frame.subflow_id << " }\n";
  return os;
}

}  // namespace net
