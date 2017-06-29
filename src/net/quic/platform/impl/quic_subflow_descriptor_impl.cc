/*
 * quic_subflow_descriptor_impl.cpp
 *
 *  Created on: Jun 6, 2017
 *      Author: cyrill
 */

#include "net/quic/platform/impl/quic_subflow_descriptor_impl.h"

namespace net {

QuicSubflowDescriptorImpl::QuicSubflowDescriptorImpl()
    : initialized_(false) {
}

QuicSubflowDescriptorImpl::QuicSubflowDescriptorImpl(QuicSocketAddress self,
    QuicSocketAddress peer)
    : self_(self), peer_(peer), initialized_(true) {
}

bool operator==(const QuicSubflowDescriptorImpl& lhs,
    const QuicSubflowDescriptorImpl& rhs) {
  return lhs.self_ == rhs.self_ && lhs.peer_ == rhs.peer_;
}

bool operator!=(const QuicSubflowDescriptorImpl& lhs,
    const QuicSubflowDescriptorImpl& rhs) {
  return !(lhs == rhs);
}

bool operator<(const QuicSubflowDescriptorImpl& lhs,
    const QuicSubflowDescriptorImpl& rhs) {
  return lhs.self_ < rhs.self_ || lhs.peer_ < rhs.peer_;
}

bool QuicSubflowDescriptorImpl::IsInitialized() const {
  return initialized_;
}

std::string QuicSubflowDescriptorImpl::ToString() const {
  if(!initialized_)
    return "Uninitialized subflow descriptor";
  return "{ Self address: "+self_.ToString()+ " Peer address: "+peer_.ToString()+" }";
}

} /* namespace net */
