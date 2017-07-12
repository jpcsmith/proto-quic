/*
 * quic_subflow_descriptor.cpp
 *
 *  Created on: Jun 6, 2017
 *      Author: cyrill
 */

#include "net/quic/platform/api/quic_subflow_descriptor.h"

namespace net {

QuicSubflowDescriptor::QuicSubflowDescriptor(QuicSocketAddress self, QuicSocketAddress peer)
:impl_(self,peer) {
}

bool operator==(const QuicSubflowDescriptor& lhs,
    const QuicSubflowDescriptor& rhs) {
  return lhs.impl_ == rhs.impl_;
}

bool operator!=(const QuicSubflowDescriptor& lhs,
    const QuicSubflowDescriptor& rhs) {
  return lhs.impl_ != rhs.impl_;
}

bool operator<(const QuicSubflowDescriptor& lhs,
    const QuicSubflowDescriptor& rhs) {
  return lhs.impl_ < rhs.impl_;
}

bool QuicSubflowDescriptor::IsInitialized() const {
  return impl_.IsInitialized();
}

std::string QuicSubflowDescriptor::ToString() const {
  return impl_.ToString();
}

} /* namespace net */
