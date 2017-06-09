// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_API_QUIC_SUBFLOW_DESCRIPTOR_H_
#define NET_QUIC_PLATFORM_API_QUIC_SUBFLOW_DESCRIPTOR_H_

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/impl/quic_subflow_descriptor_impl.h"
#include "net/quic/platform/api/quic_socket_address.h"

namespace net {

class QUIC_EXPORT_PRIVATE QuicSubflowDescriptor {
public:
  QuicSubflowDescriptor() = default;
  QuicSubflowDescriptor(const QuicSubflowDescriptor& other) = default;
  QuicSubflowDescriptor(QuicSocketAddress self, QuicSocketAddress peer);
  QuicSubflowDescriptor& operator=(const QuicSubflowDescriptor& other) = default;
  QuicSubflowDescriptor& operator=(QuicSubflowDescriptor&& other) = default;
  QUIC_EXPORT_PRIVATE friend bool operator==(const QuicSubflowDescriptor& lhs,
      const QuicSubflowDescriptor& rhs);
  QUIC_EXPORT_PRIVATE friend bool operator!=(const QuicSubflowDescriptor& lhs,
      const QuicSubflowDescriptor& rhs);

  bool IsInitialized() const;
  std::string ToString() const;

  const QuicSubflowDescriptorImpl& impl() const {return impl_;}

private:
  QuicSubflowDescriptorImpl impl_;
};

} /* namespace net */
#endif /* NET_QUIC_PLATFORM_API_QUIC_SUBFLOW_DESCRIPTOR_H_ */
