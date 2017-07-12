// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_FRAMES_QUIC_SUBFLOW_CLOSE_FRAME_H_
#define NET_QUIC_CORE_FRAMES_QUIC_SUBFLOW_CLOSE_FRAME_H_

#include <ostream>

#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

// A subflow_close frame announces a subflow to be closed.
struct QUIC_EXPORT_PRIVATE QuicSubflowCloseFrame {
  QuicSubflowCloseFrame() {
  }
  QuicSubflowCloseFrame(QuicSubflowId subflow_id);

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
      const QuicSubflowCloseFrame& w);

  // The id of the subflow to be closed
  QuicSubflowId subflow_id;
};

} // namespace net

#endif  // NET_QUIC_CORE_FRAMES_QUIC_SUBFLOW_CLOSE_FRAME_H_
