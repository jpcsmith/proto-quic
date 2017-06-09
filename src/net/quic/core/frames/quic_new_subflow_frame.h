// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_FRAMES_QUIC_NEW_SUBFLOW_FRAME_H_
#define NET_QUIC_CORE_FRAMES_QUIC_NEW_SUBFLOW_FRAME_H_

#include <ostream>

#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

// A new_subflow frame announces a new subflow for an existing quic connection
// and assigns it an id. TODO(cyrill): Should 5-tuple of the new subflow be
// included to mitigate man-in-the-middle attack (since first packet uses 0RTT)?
// Or is it authenticated using address validation?
struct QUIC_EXPORT_PRIVATE QuicNewSubflowFrame {
  QuicNewSubflowFrame() {
  }
  QuicNewSubflowFrame(QuicSubflowId subflow_id);

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
      const QuicNewSubflowFrame& w);

  // The id of the new subflow
  QuicSubflowId subflow_id;
};

} // namespace net

#endif  // NET_QUIC_CORE_FRAMES_QUIC_NEW_SUBFLOW_FRAME_H_
