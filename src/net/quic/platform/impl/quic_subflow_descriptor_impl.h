/*
 * quic_subflow_descriptor_impl.h
 *
 *  Created on: Jun 6, 2017
 *      Author: cyrill
 */

#ifndef NET_QUIC_PLATFORM_IMPL_QUIC_SUBFLOW_DESCRIPTOR_IMPL_H_
#define NET_QUIC_PLATFORM_IMPL_QUIC_SUBFLOW_DESCRIPTOR_IMPL_H_

#include "net/quic/platform/api/quic_socket_address.h"

namespace net {

class QUIC_EXPORT_PRIVATE QuicSubflowDescriptorImpl {
public:
  QuicSubflowDescriptorImpl();
  QuicSubflowDescriptorImpl(const QuicSubflowDescriptorImpl& other) = default;
  QuicSubflowDescriptorImpl(QuicSocketAddress self, QuicSocketAddress peer);
  QuicSubflowDescriptorImpl& operator=(const QuicSubflowDescriptorImpl& other) = default;
  QuicSubflowDescriptorImpl& operator=(QuicSubflowDescriptorImpl&& other) = default;
  QUIC_EXPORT_PRIVATE friend bool operator==(const QuicSubflowDescriptorImpl& lhs,
      const QuicSubflowDescriptorImpl& rhs);
  QUIC_EXPORT_PRIVATE friend bool operator!=(const QuicSubflowDescriptorImpl& lhs,
      const QuicSubflowDescriptorImpl& rhs);

  bool IsInitialized() const;
  std::string ToString() const;

private:
  QuicSocketAddress self_, peer_;

  bool initialized_;
};

} /* namespace net */
#endif /* NET_QUIC_PLATFORM_IMPL_QUIC_SUBFLOW_DESCRIPTOR_IMPL_H_ */
