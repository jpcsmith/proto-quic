// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_crypto_server_stream.h"

#include <memory>
#include <numeric>
#include <algorithm>

#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/crypto_utils.h"
#include "net/quic/core/crypto/quic_crypto_server_config.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

using std::string;

namespace net {


QuicCryptoServerStreamBase::QuicCryptoServerStreamBase(QuicSession* session)
    : QuicCryptoStream(session) {}

// TODO(jokulik): Once stateless rejects support is inherent in the version
// number, this function will likely go away entirely.
// static
bool QuicCryptoServerStreamBase::DoesPeerSupportStatelessRejects(
    const CryptoHandshakeMessage& message) {
  const QuicTag* received_tags;
  size_t received_tags_length;
  QuicErrorCode error =
      message.GetTaglist(kCOPT, &received_tags, &received_tags_length);
  if (error != QUIC_NO_ERROR) {
    return false;
  }
  for (size_t i = 0; i < received_tags_length; ++i) {
    if (received_tags[i] == kSREJ) {
      return true;
    }
  }
  return false;
}

QuicCryptoServerStream::QuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    bool use_stateless_rejects_if_peer_supported,
    QuicSession* session,
    Helper* helper)
    : QuicCryptoServerStreamBase(session),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      signed_config_(new QuicSignedServerConfig),
      helper_(helper),
      use_stateless_rejects_if_peer_supported_(
          use_stateless_rejects_if_peer_supported),
      peer_supports_stateless_rejects_(false){
  DCHECK_EQ(Perspective::IS_SERVER, session->AnyConnection()->perspective());
  AddConnectionState(session->InitialConnection());
}

QuicCryptoServerStream::~QuicCryptoServerStream() {
  CancelOutstandingCallbacks();
}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState* QuicCryptoServerStream::
GetServerConnectionState(const QuicConnection* connection) const {
  return (QuicCryptoServerStreamConnectionState*)GetConnectionState(connection);
}

void QuicCryptoServerStream::AddConnectionState(QuicConnection* connection) {
  QuicCryptoStream::AddConnectionState(connection,
      new QuicCryptoServerStreamConnectionState(connection, this));
}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
QuicCryptoServerStreamConnectionState(QuicConnection* connection,
                  QuicCryptoServerStream* stream) :
                  QuicCryptoStreamConnectionState(connection),
                  num_handshake_messages_(0),
                  num_handshake_messages_with_server_nonces_(0),
                  send_server_config_update_cb_(nullptr),
                  num_server_config_update_messages_sent_(0),
                  zero_rtt_attempted_(false),
                  validate_client_hello_cb_(nullptr),
                  process_client_hello_cb_(nullptr),
                  chlo_packet_size_(0),
                  stream_(stream)  {
}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
~QuicCryptoServerStreamConnectionState() {
  if (validate_client_hello_cb_) {
    validate_client_hello_cb_->Cancel();
  }
  if (process_client_hello_cb_) {
    process_client_hello_cb_->Cancel();
  }
  if (send_server_config_update_cb_) {
    send_server_config_update_cb_->Cancel();
  }
}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
ProcessClientHelloCallback::ProcessClientHelloCallback(
    QuicCryptoServerStreamConnectionState* parent,
    const QuicReferenceCountedPointer<
        ValidateClientHelloResultCallback::Result>& result)
    : parent_(parent), result_(result) {}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
ProcessClientHelloCallback::~ProcessClientHelloCallback() {}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
ProcessClientHelloCallback::Run(QuicErrorCode error,
         const std::string& error_details,
         std::unique_ptr<CryptoHandshakeMessage> message,
         std::unique_ptr<DiversificationNonce> diversification_nonce,
         std::unique_ptr<net::ProofSource::Details> proof_source_details) {
  if (parent_ == nullptr) {
    return;
  }

  parent_->FinishProcessingHandshakeMessageAfterProcessClientHello(
      *result_, error, error_details, std::move(message),
      std::move(diversification_nonce), std::move(proof_source_details));
}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
ProcessClientHelloCallback::Cancel() { parent_ = nullptr; }

void QuicCryptoServerStream::CancelOutstandingCallbacks() {
  // Detach from the validation callback.  Calling this multiple times is safe.
  for(auto it = connection_states_.begin(); it != connection_states_.end(); ++it) {
    QuicCryptoServerStreamConnectionState* cs = (QuicCryptoServerStreamConnectionState*)
        it->second.get();
  if (cs->validate_client_hello_cb_ != nullptr) {
    cs->validate_client_hello_cb_->Cancel();
    cs->validate_client_hello_cb_ = nullptr;
  }
  if (cs->send_server_config_update_cb_ != nullptr) {
    cs->send_server_config_update_cb_->Cancel();
    cs->send_server_config_update_cb_ = nullptr;
  }
  if (cs->process_client_hello_cb_ != nullptr) {
    cs->process_client_hello_cb_->Cancel();
    cs->process_client_hello_cb_ = nullptr;
  }
  }
}

void QuicCryptoServerStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QuicCryptoServerStreamBase::OnHandshakeMessage(message);

  if(connection_states_.find(message.Connection()) == connection_states_.end()) {
    AddConnectionState(message.Connection());
  }
  QuicCryptoServerStreamConnectionState* cs = GetServerConnectionState(message.Connection());

  ++cs->num_handshake_messages_;
  cs->chlo_packet_size_ = cs->Connection()->GetCurrentPacket().length();

  // Do not process handshake messages after the handshake is confirmed.
  if (cs->handshake_confirmed_) {
    CloseConnectionWithDetails(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE,
                               "Unexpected handshake message from client");
    return;
  }

  if (message.tag() != kCHLO) {
    CloseConnectionWithDetails(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                               "Handshake packet not CHLO");
    return;
  }

  if (cs->validate_client_hello_cb_ != nullptr ||
      cs->process_client_hello_cb_ != nullptr) {
    // Already processing some other handshake message.  The protocol
    // does not allow for clients to send multiple handshake messages
    // before the server has a chance to respond.
    CloseConnectionWithDetails(
        QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO,
        "Unexpected handshake message while processing CHLO");
    return;
  }

  CryptoUtils::HashHandshakeMessage(message, &chlo_hash_,
                                    Perspective::IS_SERVER);

  std::unique_ptr<QuicCryptoServerStreamConnectionState::ValidateCallback>
  cb(new QuicCryptoServerStreamConnectionState::ValidateCallback(cs));
  DCHECK(cs->validate_client_hello_cb_ == nullptr);
  DCHECK(cs->process_client_hello_cb_ == nullptr);
  cs->validate_client_hello_cb_ = cb.get();
  crypto_config_->ValidateClientHello(
      message, GetClientAddress(cs).host(),
      cs->Connection()->self_address(), version(),
      cs->Connection()->clock(), signed_config_, std::move(cb));
}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
FinishProcessingHandshakeMessage(
    QuicReferenceCountedPointer<ValidateClientHelloResultCallback::Result>
        result,
    std::unique_ptr<ProofSource::Details> details) {
  stream_->FinishProcessingHandshakeMessage(this, result, std::move(details));
}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
    FinishProcessingHandshakeMessageAfterProcessClientHello(
        const ValidateClientHelloResultCallback::Result& result,
        QuicErrorCode error,
        const string& error_details,
        std::unique_ptr<CryptoHandshakeMessage> reply,
        std::unique_ptr<DiversificationNonce> diversification_nonce,
        std::unique_ptr<ProofSource::Details> proof_source_details) {
  stream_->FinishProcessingHandshakeMessageAfterProcessClientHello(
      this, result, error, error_details, std::move(reply),
      std::move(diversification_nonce), std::move(proof_source_details));
}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
FinishSendServerConfigUpdate(bool ok,
    const CryptoHandshakeMessage& message) {
  stream_->FinishSendServerConfigUpdate(this, ok, message);
}

void QuicCryptoServerStream::FinishProcessingHandshakeMessage(
    QuicCryptoServerStreamConnectionState* cs,
    QuicReferenceCountedPointer<ValidateClientHelloResultCallback::Result>
        result,
    std::unique_ptr<ProofSource::Details> details) {
  const CryptoHandshakeMessage& message = result->client_hello;

  // Clear the callback that got us here.
  DCHECK(cs->validate_client_hello_cb_ != nullptr);
  DCHECK(cs->process_client_hello_cb_ == nullptr);
  cs->validate_client_hello_cb_ = nullptr;

  if (use_stateless_rejects_if_peer_supported_) {
    peer_supports_stateless_rejects_ = DoesPeerSupportStatelessRejects(message);
  }

  std::unique_ptr<QuicCryptoServerStreamConnectionState::ProcessClientHelloCallback> cb(
      new QuicCryptoServerStreamConnectionState::ProcessClientHelloCallback(cs, result));
  cs->process_client_hello_cb_ = cb.get();
  ProcessClientHello(cs, result, std::move(details), std::move(cb));
}

void QuicCryptoServerStream::
    FinishProcessingHandshakeMessageAfterProcessClientHello(
        QuicCryptoServerStreamConnectionState* cs,
        const ValidateClientHelloResultCallback::Result& result,
        QuicErrorCode error,
        const string& error_details,
        std::unique_ptr<CryptoHandshakeMessage> reply,
        std::unique_ptr<DiversificationNonce> diversification_nonce,
        std::unique_ptr<ProofSource::Details> proof_source_details) {
  // Clear the callback that got us here.
  DCHECK(cs->process_client_hello_cb_ != nullptr);
  DCHECK(cs->validate_client_hello_cb_ == nullptr);
  cs->process_client_hello_cb_ = nullptr;

  const CryptoHandshakeMessage& message = result.client_hello;
  if (error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(error, error_details);
    return;
  }

  if (reply->tag() != kSHLO) {
    if (reply->tag() == kSREJ) {
      DCHECK(use_stateless_rejects_if_peer_supported_);
      DCHECK(peer_supports_stateless_rejects_);
      // Before sending the SREJ, cause the connection to save crypto packets
      // so that they can be added to the time wait list manager and
      // retransmitted.
      cs->Connection()->EnableSavingCryptoPackets();
    }
    SendHandshakeMessage(*reply);

    if (reply->tag() == kSREJ) {
      DCHECK(use_stateless_rejects_if_peer_supported_);
      DCHECK(peer_supports_stateless_rejects_);
      DCHECK(!cs->handshake_confirmed());
      QUIC_DLOG(INFO) << "Closing connection "
                      << cs->Connection()->connection_id()
                      << " because of a stateless reject.";
      session()->CloseConnection(
          QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT, "stateless reject",
          ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return;
  }

  // If we are returning a SHLO then we accepted the handshake.  Now
  // process the negotiated configuration options as part of the
  // session config.
  QuicConfig* config = session()->config();
  OverrideQuicConfigDefaults(config);
  string process_error_details;
  const QuicErrorCode process_error =
      config->ProcessPeerHello(message, CLIENT, &process_error_details);
  if (process_error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(process_error, process_error_details);
    return;
  }

  session()->OnConfigNegotiated(cs->Connection());

  config->ToHandshakeMessage(reply.get());

  // Receiving a full CHLO implies the client is prepared to decrypt with
  // the new server write key.  We can start to encrypt with the new server
  // write key.
  //
  // NOTE: the SHLO will be encrypted with the new server write key.
  cs->Connection()->SetEncrypter(
      ENCRYPTION_INITIAL,
      cs->crypto_negotiated_params_->initial_crypters.encrypter.release());
  cs->Connection()->SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Set the decrypter immediately so that we no longer accept unencrypted
  // packets.
  cs->Connection()->SetDecrypter(
      ENCRYPTION_INITIAL,
      cs->crypto_negotiated_params_->initial_crypters.decrypter.release());
  cs->Connection()->SetDiversificationNonce(*diversification_nonce);

  SendHandshakeMessage(*reply);

  cs->Connection()->SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      cs->crypto_negotiated_params_->forward_secure_crypters.encrypter.release());
  cs->Connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  cs->Connection()->SetAlternativeDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      cs->crypto_negotiated_params_->forward_secure_crypters.decrypter.release(),
      false /* don't latch */);

  cs->encryption_established_ = true;
  cs->handshake_confirmed_ = true;
  session()->OnCryptoHandshakeEvent(cs->Connection(), QuicSession::HANDSHAKE_CONFIRMED);
}

void QuicCryptoServerStream::SendServerConfigUpdate(QuicConnection* connection,
    const CachedNetworkParameters* cached_network_params) {
  DCHECK(GetServerConnectionState(connection) != nullptr);
  QuicCryptoServerStreamConnectionState* cs = GetServerConnectionState(connection);

  if (!cs->handshake_confirmed_) {
    return;
  }

  if (cs->send_server_config_update_cb_ != nullptr) {
    QUIC_DVLOG(1)
        << "Skipped server config update since one is already in progress";
    return;
  }

  std::unique_ptr<QuicCryptoServerStreamConnectionState::SendServerConfigUpdateCallback> cb(
      new QuicCryptoServerStreamConnectionState::SendServerConfigUpdateCallback(cs));
  cs->send_server_config_update_cb_ = cb.get();

  crypto_config_->BuildServerConfigUpdateMessage(
      cs->Connection()->version(), chlo_hash_,
      cs->previous_source_address_tokens_, cs->Connection()->self_address(),
      GetClientAddress(cs).host(), cs->Connection()->clock(),
      cs->Connection()->random_generator(), compressed_certs_cache_,
      *cs->crypto_negotiated_params_, cached_network_params,
      (session()->config()->HasReceivedConnectionOptions()
           ? session()->config()->ReceivedConnectionOptions()
           : QuicTagVector()),
      std::move(cb));
}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
SendServerConfigUpdateCallback::SendServerConfigUpdateCallback(
    QuicCryptoServerStreamConnectionState* parent)
    : parent_(parent) {}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
SendServerConfigUpdateCallback::Cancel() {
  parent_ = nullptr;
}

// From BuildServerConfigUpdateMessageResultCallback
void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::
SendServerConfigUpdateCallback::Run(
    bool ok,
    const CryptoHandshakeMessage& message) {
  if (parent_ == nullptr) {
    return;
  }
  parent_->FinishSendServerConfigUpdate(ok, message);
}

void QuicCryptoServerStream::FinishSendServerConfigUpdate(
    QuicCryptoServerStreamConnectionState* cs,
    bool ok,
    const CryptoHandshakeMessage& message) {
  // Clear the callback that got us here.
  DCHECK(cs->send_server_config_update_cb_ != nullptr);
  cs->send_server_config_update_cb_ = nullptr;

  if (!ok) {
    QUIC_DVLOG(1) << "Server: Failed to build server config update (SCUP)!";
    return;
  }

  QUIC_DVLOG(1) << "Server: Sending server config update: "
                << message.DebugString(Perspective::IS_SERVER);
  const QuicData& data = message.GetSerialized(Perspective::IS_SERVER);
  WriteOrBufferData(QuicStringPiece(data.data(), data.length()), false,
                    nullptr, cs->Connection());

  ++cs->num_server_config_update_messages_sent_;
}

uint8_t QuicCryptoServerStream::NumHandshakeMessages() const {
  return std::accumulate(
      connection_states_.begin(),connection_states_.end(),
      0,
      [](const size_t previous,
         const std::pair<QuicConnection* const,
         std::unique_ptr<QuicCryptoStreamConnectionState>>& p) {
    QuicCryptoServerStreamConnectionState* cs =
        (QuicCryptoServerStreamConnectionState*)p.second.get();
    return previous+cs->num_handshake_messages_;
  });
}

uint8_t QuicCryptoServerStream::NumHandshakeMessagesWithServerNonces() const {
  return std::accumulate(
      connection_states_.begin(),connection_states_.end(),
      0,
      [](const size_t previous,
         const std::pair<QuicConnection* const,
         std::unique_ptr<QuicCryptoStreamConnectionState>>& p) {
    QuicCryptoServerStreamConnectionState* cs =
        (QuicCryptoServerStreamConnectionState*)p.second.get();
    return previous+cs->num_handshake_messages_with_server_nonces_;
  });
}

int QuicCryptoServerStream::NumServerConfigUpdateMessagesSent() const {
  return std::accumulate(
      connection_states_.begin(),connection_states_.end(),
      0,
      [](const size_t previous,
         const std::pair<QuicConnection* const,
         std::unique_ptr<QuicCryptoStreamConnectionState>>& p) {
    QuicCryptoServerStreamConnectionState* cs =
        (QuicCryptoServerStreamConnectionState*)p.second.get();
    return previous+cs->num_server_config_update_messages_sent_;
  });
}

const CachedNetworkParameters*
QuicCryptoServerStream::PreviousCachedNetworkParams(QuicConnection* connection) const {
  QuicCryptoServerStreamConnectionState* cs = GetServerConnectionState(connection);
  return cs->previous_cached_network_params_.get();
}

bool QuicCryptoServerStream::UseStatelessRejectsIfPeerSupported() const {
  return use_stateless_rejects_if_peer_supported_;
}

bool QuicCryptoServerStream::PeerSupportsStatelessRejects() const {
  return peer_supports_stateless_rejects_;
}

bool QuicCryptoServerStream::ZeroRttAttempted() const {
  return std::any_of(
      connection_states_.begin(),connection_states_.end(),
      [](const std::pair<QuicConnection* const,
         std::unique_ptr<QuicCryptoStreamConnectionState>>& p) {
    return ((QuicCryptoServerStreamConnectionState*)p.second.get())->zero_rtt_attempted_;
  });
}

void QuicCryptoServerStream::SetPeerSupportsStatelessRejects(
    bool peer_supports_stateless_rejects) {
  peer_supports_stateless_rejects_ = peer_supports_stateless_rejects;
}

void QuicCryptoServerStream::SetPreviousCachedNetworkParams(
    QuicConnection* connection, CachedNetworkParameters cached_network_params) {
  QuicCryptoServerStreamConnectionState* cs = GetServerConnectionState(connection);
  return cs->previous_cached_network_params_.reset(
      new CachedNetworkParameters(cached_network_params));
}

bool QuicCryptoServerStream::GetBase64SHA256ClientChannelID(
    QuicConnection* connection, string* output) const {
  QuicCryptoServerStreamConnectionState* cs = GetServerConnectionState(connection);
  if (!cs->encryption_established_ ||
      cs->crypto_negotiated_params_->channel_id.empty()) {
    return false;
  }

  const string& channel_id(cs->crypto_negotiated_params_->channel_id);
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t*>(channel_id.data()), channel_id.size(),
         digest);

  QuicTextUtils::Base64Encode(digest, arraysize(digest), output);
  return true;
}

void QuicCryptoServerStream::ProcessClientHello(
    QuicCryptoServerStreamConnectionState* cs,
    QuicReferenceCountedPointer<ValidateClientHelloResultCallback::Result>
        result,
    std::unique_ptr<ProofSource::Details> proof_source_details,
    std::unique_ptr<ProcessClientHelloResultCallback> done_cb) {
  const CryptoHandshakeMessage& message = result->client_hello;
  string error_details;
  if (!helper_->CanAcceptClientHello(
          message, cs->Connection()->self_address(), &error_details)) {
    done_cb->Run(QUIC_HANDSHAKE_FAILED, error_details, nullptr, nullptr,
                 nullptr);
    return;
  }
  if (!result->info.server_nonce.empty()) {
    ++cs->num_handshake_messages_with_server_nonces_;
  }

  if (cs->num_handshake_messages_ == 1) {
    // Client attempts zero RTT handshake by sending a non-inchoate CHLO.
    QuicStringPiece public_value;
    cs->zero_rtt_attempted_ = message.GetStringPiece(kPUBS, &public_value);
  }

  // Store the bandwidth estimate from the client.
  if (result->cached_network_params.bandwidth_estimate_bytes_per_second() > 0) {
    cs->previous_cached_network_params_.reset(
        new CachedNetworkParameters(result->cached_network_params));
  }
  cs->previous_source_address_tokens_ = result->info.source_address_tokens;

  const bool use_stateless_rejects_in_crypto_config =
      use_stateless_rejects_if_peer_supported_ &&
      peer_supports_stateless_rejects_;
  const QuicConnectionId server_designated_connection_id =
      GenerateConnectionIdForReject(cs, use_stateless_rejects_in_crypto_config);
  crypto_config_->ProcessClientHello(
      result, /*reject_only=*/false, cs->Connection()->connection_id(),
      cs->Connection()->self_address(), GetClientAddress(cs), version(),
      cs->Connection()->supported_versions(), use_stateless_rejects_in_crypto_config,
      server_designated_connection_id, cs->Connection()->clock(),
      cs->Connection()->random_generator(), compressed_certs_cache_,
      cs->crypto_negotiated_params_, signed_config_,
      QuicCryptoStream::CryptoMessageFramingOverhead(version()),
      cs->chlo_packet_size_, std::move(done_cb));
}

void QuicCryptoServerStream::OverrideQuicConfigDefaults(QuicConfig* config) {}

QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::ValidateCallback::
ValidateCallback(QuicCryptoServerStreamConnectionState* parent)
    : parent_(parent) {}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::ValidateCallback::Cancel() {
  parent_ = nullptr;
}

void QuicCryptoServerStream::QuicCryptoServerStreamConnectionState::ValidateCallback::Run(
    QuicReferenceCountedPointer<Result> result,
    std::unique_ptr<ProofSource::Details> details) {
  if (parent_ != nullptr) {
    parent_->FinishProcessingHandshakeMessage(std::move(result),
                                              std::move(details));
  }
}

QuicConnectionId QuicCryptoServerStream::GenerateConnectionIdForReject(
    QuicCryptoServerStreamConnectionState* cs,
    bool use_stateless_rejects) {
  if (!use_stateless_rejects) {
    return 0;
  }
  return helper_->GenerateConnectionIdForReject(
      cs->Connection()->connection_id());
}

const QuicSocketAddress QuicCryptoServerStream::GetClientAddress(
    QuicCryptoServerStreamConnectionState* cs) {
  return cs->Connection()->peer_address();
}

}  // namespace net
