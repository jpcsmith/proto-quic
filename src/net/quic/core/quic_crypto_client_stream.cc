// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_crypto_client_stream.h"

#include <memory>

#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/crypto_utils.h"
#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_str_cat.h"

using std::string;

namespace net {

const int QuicCryptoClientStream::kMaxClientHellos;

QuicCryptoClientStreamBase::QuicCryptoClientStreamBase(QuicSession* session)
    : QuicCryptoStream(session) {}

QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ChannelIDSourceCallbackImpl::
    ChannelIDSourceCallbackImpl(QuicCryptoClientStreamConnectionState* connection_state)
    : connection_state_(connection_state) {}

QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ChannelIDSourceCallbackImpl::
    ~ChannelIDSourceCallbackImpl() {}

void QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ChannelIDSourceCallbackImpl::Run(
    std::unique_ptr<ChannelIDKey>* channel_id_key) {
  if (connection_state_ == nullptr) {
    return;
  }

  connection_state_->channel_id_key_ = std::move(*channel_id_key);
  connection_state_->channel_id_source_callback_run_ = true;
  connection_state_->channel_id_source_callback_ = nullptr;
  connection_state_->GetChannelIdComplete();

  // The ChannelIDSource owns this object and will delete it when this method
  // returns.
}

void QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ChannelIDSourceCallbackImpl::Cancel() {
  connection_state_ = nullptr;
}

QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ProofVerifierCallbackImpl::ProofVerifierCallbackImpl(
    QuicCryptoClientStreamConnectionState* connection_state)
    : connection_state_(connection_state) {}

QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ProofVerifierCallbackImpl::
    ~ProofVerifierCallbackImpl() {}

void QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ProofVerifierCallbackImpl::Run(
    bool ok,
    const string& error_details,
    std::unique_ptr<ProofVerifyDetails>* details) {
  if (connection_state_ == nullptr) {
    return;
  }

  connection_state_->verify_ok_ = ok;
  connection_state_->verify_error_details_ = error_details;
  connection_state_->verify_details_ = std::move(*details);
  connection_state_->proof_verify_callback_ = nullptr;
  connection_state_->ProofVerifyComplete();

  // The ProofVerifier owns this object and will delete it when this method
  // returns.
}

void QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::ProofVerifierCallbackImpl::Cancel() {
  connection_state_ = nullptr;
}

QuicCryptoClientStream::QuicCryptoClientStream(
    const QuicServerId& server_id,
    QuicSession* session,
    ProofVerifyContext* verify_context,
    QuicCryptoClientConfig* crypto_config,
    ProofHandler* proof_handler)
    : QuicCryptoClientStreamBase(session),
      crypto_config_(crypto_config) {
  DCHECK_EQ(Perspective::IS_CLIENT, session->AnyConnection()->perspective());
  AddConnectionState(session->connection_manager()->InitialConnection(),
      verify_context,server_id,proof_handler);
}

QuicCryptoClientStream::~QuicCryptoClientStream() {}

void QuicCryptoClientStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QuicCryptoClientStreamBase::OnHandshakeMessage(message);

  if(connection_states_.find(connection) == connection_states_.end()) {
    AddConnectionState(connection);
  }

  DCHECK(connection_states_.find(message.Connection()) != connection_states_.end());
  QuicCryptoClientStreamConnectionState* cs = connection_states_[message.Connection()];

  if (message.tag() == kSCUP) {
    if (!cs->handshake_confirmed()) {
      CloseConnectionWithDetails(QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE,
                                 "Early SCUP disallowed");
      return;
    }

    // |message| is an update from the server, so we treat it differently from a
    // handshake message.
    HandleServerConfigUpdateMessage(cs,message);
    cs->num_scup_messages_received_++;
    return;
  }

  // Do not process handshake messages after the handshake is confirmed.
  if (cs->handshake_confirmed()) {
    CloseConnectionWithDetails(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE,
                               "Unexpected handshake message");
    return;
  }

  DoHandshakeLoop(cs, &message);
}

void QuicCryptoClientStream::AddConnectionState(QuicConnection* connection) {
  // Create a new state for this connection using the same privacy mode but
  // adjust the server address for the new connection (the server address
  // might be different since we allow multipathing).
  QuicCryptoClientStreamConnectionState* anyCS = connection_states_.begin()->second;
  QuicServerId sid(connection->SubflowDescriptor().Peer(),anyCS->server_id_.privacy_mode());
  AddConnectionState(connection, anyCS->verify_context_, sid, anyCS->proof_handler_);
}

void QuicCryptoClientStream::AddConnectionState(QuicConnection* connection,
                        ProofVerifyContext* verify_context,
                        const QuicServerId& server_id,
                        ProofHandler* proof_handler) {
  QuicCryptoStream::AddConnectionState(connection,
      new QuicCryptoClientStreamConnectionState(
          connection, verify_context, server_id, proof_handler, this));
}

QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::
QuicCryptoClientStreamConnectionState(
                QuicConnection* connection,
                ProofVerifyContext* verify_context,
                const QuicServerId& server_id,
                ProofHandler* proof_handler,
                QuicCryptoClientStream* stream) :
  QuicCryptoStreamConnectionState(connection),
  next_state_(STATE_IDLE),
  num_client_hellos_(0),
  server_id_(server_id),
  generation_counter_(0),
  channel_id_sent_(false),
  channel_id_source_callback_run_(false),
  channel_id_source_callback_(nullptr),
  verify_context_(verify_context),
  proof_verify_callback_(nullptr),
  proof_handler_(proof_handler),
  verify_ok_(false),
  stateless_reject_received_(false),
  num_scup_messages_received_(0),
  stream_(stream) {
}

QuicCryptoClientStream::QuicCryptoClientStreamConnectionState::
~QuicCryptoClientStreamConnectionState() {
  if (channel_id_source_callback_) {
    channel_id_source_callback_->Cancel();
  }
  if (proof_verify_callback_) {
    proof_verify_callback_->Cancel();
  }
}

bool QuicCryptoClientStream::CryptoConnect(QuicConnection* connection) {
  QuicCryptoClientStreamConnectionState* cs;
  if(connection_states_.find(connection) == connection_states_.end()) {
    AddConnectionState(connection);
  }
  cs = connection_states_[connection];
  cs->next_state_ = STATE_INITIALIZE;
  DoHandshakeLoop(cs, nullptr);
  return session()->connected();
}

int QuicCryptoClientStream::num_sent_client_hellos() const {
  return connection_states_[session()->InitialConnection()]->num_sent_client_hellos();
}

int QuicCryptoClientStream::num_scup_messages_received() const {
  return connection_states_[session()->InitialConnection()]->num_scup_messages_received();
}

void QuicCryptoClientStream::HandleServerConfigUpdateMessage(
    QuicCryptoClientStreamConnectionState* cs,
    const CryptoHandshakeMessage& server_config_update) {
  DCHECK(server_config_update.tag() == kSCUP);
  string error_details;
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_->LookupOrCreate(cs->server_id_);
  QuicErrorCode error = crypto_config_->ProcessServerConfigUpdate(
      server_config_update, cs->Connection()->clock()->WallNow(),
      cs->Connection()->version(), chlo_hash_, cached,
      cs->crypto_negotiated_params_, &error_details);

  if (error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(
        error, "Server config update invalid: " + error_details);
    return;
  }

  DCHECK(cs->handshake_confirmed());
  if (cs->proof_verify_callback_) {
    cs->proof_verify_callback_->Cancel();
  }
  cs->next_state_ = STATE_INITIALIZE_SCUP;
  DoHandshakeLoop(cs, nullptr);
}

void QuicCryptoClientStream::DoHandshakeLoop(
    QuicCryptoClientStreamConnectionState* cs,
    const CryptoHandshakeMessage* in) {
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_->LookupOrCreate(cs->server_id_);

  QuicAsyncStatus rv = QUIC_SUCCESS;
  do {
    CHECK_NE(STATE_NONE, cs->next_state_);
    const State state = cs->next_state_;
    cs->next_state_ = STATE_IDLE;
    rv = QUIC_SUCCESS;
    switch (state) {
      case STATE_INITIALIZE:
        DoInitialize(cs, cached);
        break;
      case STATE_SEND_CHLO:
        DoSendCHLO(cs, cached);
        return;  // return waiting to hear from server.
      case STATE_RECV_REJ:
        DoReceiveREJ(cs, in, cached);
        break;
      case STATE_VERIFY_PROOF:
        rv = DoVerifyProof(cs, cached);
        break;
      case STATE_VERIFY_PROOF_COMPLETE:
        DoVerifyProofComplete(cs, cached);
        break;
      case STATE_GET_CHANNEL_ID:
        rv = DoGetChannelID(cs, cached);
        break;
      case STATE_GET_CHANNEL_ID_COMPLETE:
        DoGetChannelIDComplete(cs);
        break;
      case STATE_RECV_SHLO:
        DoReceiveSHLO(cs, in, cached);
        break;
      case STATE_IDLE:
        // This means that the peer sent us a message that we weren't expecting.
        CloseConnectionWithDetails(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                                   "Handshake in idle state");
        return;
      case STATE_INITIALIZE_SCUP:
        DoInitializeServerConfigUpdate(cs, cached);
        break;
      case STATE_NONE:
        QUIC_NOTREACHED();
        return;  // We are done.
    }
  } while (rv != QUIC_PENDING && cs->next_state_ != STATE_NONE);
}

void QuicCryptoClientStream::DoInitialize(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  if (!cached->IsEmpty() && !cached->signature().empty()) {
    // Note that we verify the proof even if the cached proof is valid.
    // This allows us to respond to CA trust changes or certificate
    // expiration because it may have been a while since we last verified
    // the proof.
    DCHECK(crypto_config_->proof_verifier());
    // Track proof verification time when cached server config is used.
    cs->proof_verify_start_time_ = base::TimeTicks::Now();
    chlo_hash_ = cached->chlo_hash();
    // If the cached state needs to be verified, do it now.
    cs->next_state_ = STATE_VERIFY_PROOF;
  } else {
    cs->next_state_ = STATE_GET_CHANNEL_ID;
  }
}

void QuicCryptoClientStream::DoSendCHLO(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  if (cs->stateless_reject_received_) {
    // If we've gotten to this point, we've sent at least one hello
    // and received a stateless reject in response.  We cannot
    // continue to send hellos because the server has abandoned state
    // for this connection.  Abandon further handshakes.
    cs->next_state_ = STATE_NONE;
    if (session()->connected()) {
      session()->CloseConnection(
          QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT, "stateless reject received",
          ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return;
  }

  // Send the client hello in plaintext.
  cs->Connection()->SetDefaultEncryptionLevel(ENCRYPTION_NONE);
  cs->encryption_established_ = false;
  if (cs->num_client_hellos_ > kMaxClientHellos) {
    //TODO(cyrill) Close connection, or just close subflow?
    CloseConnectionWithDetails(
        QUIC_CRYPTO_TOO_MANY_REJECTS,
        QuicStrCat("More than ", kMaxClientHellos, " rejects"));
    return;
  }
  cs->num_client_hellos_++;

  CryptoHandshakeMessage out;
  DCHECK(session() != nullptr);
  DCHECK(session()->config() != nullptr);
  out.SetConnection(cs->Connection());
  // Send all the options, regardless of whether we're sending an
  // inchoate or subsequent hello.
  session()->config()->ToHandshakeMessage(&out);

  // Send a local timestamp to the server.
  out.SetValue(kCTIM,
               cs->Connection()->clock()->WallNow().ToUNIXSeconds());

  if (!cached->IsComplete(cs->Connection()->clock()->WallNow())) {
    crypto_config_->FillInchoateClientHello(
        cs->server_id_, cs->Connection()->supported_versions().front(),
        cached, cs->Connection()->random_generator(),
        /* demand_x509_proof= */ true, cs->crypto_negotiated_params_, &out);
    // Pad the inchoate client hello to fill up a packet.
    const QuicByteCount kFramingOverhead = 50;  // A rough estimate.
    const QuicByteCount max_packet_size =
        cs->Connection()->max_packet_length();
    if (max_packet_size <= kFramingOverhead) {
      QUIC_DLOG(DFATAL) << "max_packet_length (" << max_packet_size
                        << ") has no room for framing overhead.";
      CloseConnectionWithDetails(QUIC_INTERNAL_ERROR,
                                 "max_packet_size too smalll");
      return;
    }
    if (kClientHelloMinimumSize > max_packet_size - kFramingOverhead) {
      QUIC_DLOG(DFATAL) << "Client hello won't fit in a single packet.";
      CloseConnectionWithDetails(QUIC_INTERNAL_ERROR, "CHLO too large");
      return;
    }
    // TODO(rch): Remove this when we remove:
    // FLAGS_quic_reloadable_flag_quic_use_chlo_packet_size
    out.set_minimum_size(
        static_cast<size_t>(max_packet_size - kFramingOverhead));
    cs->next_state_ = STATE_RECV_REJ;
    CryptoUtils::HashHandshakeMessage(out, &chlo_hash_, Perspective::IS_CLIENT);
    SendHandshakeMessage(out);
    return;
  }

  // If the server nonce is empty, copy over the server nonce from a previous
  // SREJ, if there is one.
  if (FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support &&
      cs->crypto_negotiated_params_->server_nonce.empty() &&
      cached->has_server_nonce()) {
    cs->crypto_negotiated_params_->server_nonce = cached->GetNextServerNonce();
    DCHECK(!cs->crypto_negotiated_params_->server_nonce.empty());
  }

  string error_details;
  QuicErrorCode error = crypto_config_->FillClientHello(
      cs->server_id_, cs->Connection()->connection_id(),
      cs->Connection()->supported_versions().front(), cached,
      cs->Connection()->clock()->WallNow(),
      cs->Connection()->random_generator(), cs->channel_id_key_.get(),
      cs->crypto_negotiated_params_, &out, &error_details);
  if (error != QUIC_NO_ERROR) {
    // Flush the cached config so that, if it's bad, the server has a
    // chance to send us another in the future.
    cached->InvalidateServerConfig();
    CloseConnectionWithDetails(error, error_details);
    return;
  }
  CryptoUtils::HashHandshakeMessage(out, &chlo_hash_, Perspective::IS_CLIENT);
  cs->channel_id_sent_ = (cs->channel_id_key_.get() != nullptr);
  if (cached->proof_verify_details()) {
    cs->proof_handler_->OnProofVerifyDetailsAvailable(
        *cached->proof_verify_details());
  }
  cs->next_state_ = STATE_RECV_SHLO;
  SendHandshakeMessage(out);
  // Be prepared to decrypt with the new server write key.
  cs->Connection()->SetAlternativeDecrypter(
      ENCRYPTION_INITIAL,
      cs->crypto_negotiated_params_->initial_crypters.decrypter.release(),
      true /* latch once used */);
  // Send subsequent packets under encryption on the assumption that the
  // server will accept the handshake.
  cs->Connection()->SetEncrypter(
      ENCRYPTION_INITIAL,
      cs->crypto_negotiated_params_->initial_crypters.encrypter.release());
  cs->Connection()->SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);

  // TODO(ianswett): Merge ENCRYPTION_REESTABLISHED and
  // ENCRYPTION_FIRST_ESTABLSIHED
  cs->encryption_established_ = true;
  session()->OnCryptoHandshakeEvent(cs->Connection(), QuicSession::ENCRYPTION_REESTABLISHED);
}

void QuicCryptoClientStream::DoReceiveREJ(
    QuicCryptoClientStreamConnectionState* cs,
    const CryptoHandshakeMessage* in,
    QuicCryptoClientConfig::CachedState* cached) {
  // We sent a dummy CHLO because we didn't have enough information to
  // perform a handshake, or we sent a full hello that the server
  // rejected. Here we hope to have a REJ that contains the information
  // that we need.
  if ((in->tag() != kREJ) && (in->tag() != kSREJ)) {
    cs->next_state_ = STATE_NONE;
    CloseConnectionWithDetails(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                               "Expected REJ");
    return;
  }

  const uint32_t* reject_reasons;
  size_t num_reject_reasons;
  static_assert(sizeof(QuicTag) == sizeof(uint32_t), "header out of sync");
  if (in->GetTaglist(kRREJ, &reject_reasons, &num_reject_reasons) ==
      QUIC_NO_ERROR) {
    uint32_t packed_error = 0;
    for (size_t i = 0; i < num_reject_reasons; ++i) {
      // HANDSHAKE_OK is 0 and don't report that as error.
      if (reject_reasons[i] == HANDSHAKE_OK || reject_reasons[i] >= 32) {
        continue;
      }
      HandshakeFailureReason reason =
          static_cast<HandshakeFailureReason>(reject_reasons[i]);
      packed_error |= 1 << (reason - 1);
    }
    DVLOG(1) << "Reasons for rejection: " << packed_error;
    if (cs->num_client_hellos_ == kMaxClientHellos) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicClientHelloRejectReasons.TooMany",
                                  packed_error);
    }
    UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicClientHelloRejectReasons.Secure",
                                packed_error);
  }

  // Receipt of a REJ message means that the server received the CHLO
  // so we can cancel and retransmissions.
  cs->Connection()->NeuterUnencryptedPackets();

  cs->stateless_reject_received_ = in->tag() == kSREJ;
  string error_details;
  QuicErrorCode error = crypto_config_->ProcessRejection(
      *in, cs->Connection()->clock()->WallNow(),
      cs->Connection()->version(), chlo_hash_, cached,
      cs->crypto_negotiated_params_, &error_details);

  if (error != QUIC_NO_ERROR) {
    cs->next_state_ = STATE_NONE;
    CloseConnectionWithDetails(error, error_details);
    return;
  }
  if (!cached->proof_valid()) {
    if (!cached->signature().empty()) {
      // Note that we only verify the proof if the cached proof is not
      // valid. If the cached proof is valid here, someone else must have
      // just added the server config to the cache and verified the proof,
      // so we can assume no CA trust changes or certificate expiration
      // has happened since then.
      cs->next_state_ = STATE_VERIFY_PROOF;
      return;
    }
  }
  cs->next_state_ = STATE_GET_CHANNEL_ID;
}

QuicAsyncStatus QuicCryptoClientStream::DoVerifyProof(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  ProofVerifier* verifier = crypto_config_->proof_verifier();
  DCHECK(verifier);
  cs->next_state_ = STATE_VERIFY_PROOF_COMPLETE;
  cs->generation_counter_ = cached->generation_counter();

  QuicCryptoClientStreamConnectionState::ProofVerifierCallbackImpl* proof_verify_callback =
      new QuicCryptoClientStreamConnectionState::ProofVerifierCallbackImpl(cs);

  cs->verify_ok_ = false;

  QuicAsyncStatus status = verifier->VerifyProof(
      cs->server_id_.host(), cs->server_id_.port(), cached->server_config(),
      cs->Connection()->version(), chlo_hash_, cached->certs(),
      cached->cert_sct(), cached->signature(), cs->verify_context_.get(),
      &cs->verify_error_details_, &cs->verify_details_,
      std::unique_ptr<ProofVerifierCallback>(proof_verify_callback));

  switch (status) {
    case QUIC_PENDING:
      cs->proof_verify_callback_ = proof_verify_callback;
      QUIC_DVLOG(1) << "Doing VerifyProof";
      break;
    case QUIC_FAILURE:
      break;
    case QUIC_SUCCESS:
      cs->verify_ok_ = true;
      break;
  }
  return status;
}

void QuicCryptoClientStream::DoVerifyProofComplete(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  if (!cs->proof_verify_start_time_.is_null()) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.VerifyProofTime.CachedServerConfig",
                        base::TimeTicks::Now() - cs->proof_verify_start_time_);
  }
  if (!cs->verify_ok_) {
    if (cs->verify_details_.get()) {
      cs->proof_handler_->OnProofVerifyDetailsAvailable(*cs->verify_details_);
    }
    if (cs->num_client_hellos_ == 0) {
      cached->Clear();
      cs->next_state_ = STATE_INITIALIZE;
      return;
    }
    cs->next_state_ = STATE_NONE;
    UMA_HISTOGRAM_BOOLEAN("Net.QuicVerifyProofFailed.HandshakeConfirmed",
                          cs->handshake_confirmed());
    CloseConnectionWithDetails(QUIC_PROOF_INVALID,
                               "Proof invalid: " + cs->verify_error_details_);
    return;
  }

  // Check if generation_counter has changed between STATE_VERIFY_PROOF and
  // STATE_VERIFY_PROOF_COMPLETE state changes.
  if (cs->generation_counter_ != cached->generation_counter()) {
    cs->next_state_ = STATE_VERIFY_PROOF;
  } else {
    SetCachedProofValid(cached);
    cached->SetProofVerifyDetails(cs->verify_details_.release());
    if (!cs->handshake_confirmed()) {
      cs->next_state_ = STATE_GET_CHANNEL_ID;
    } else {
      // TODO: Enable Expect-Staple. https://crbug.com/631101
      cs->next_state_ = STATE_NONE;
    }
  }
}

QuicAsyncStatus QuicCryptoClientStream::DoGetChannelID(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  cs->next_state_ = STATE_GET_CHANNEL_ID_COMPLETE;
  cs->channel_id_key_.reset();
  if (!RequiresChannelID(cached)) {
    cs->next_state_ = STATE_SEND_CHLO;
    return QUIC_SUCCESS;
  }

  QuicCryptoClientStreamConnectionState::ChannelIDSourceCallbackImpl* channel_id_source_callback =
      new QuicCryptoClientStreamConnectionState::ChannelIDSourceCallbackImpl(cs);
  QuicAsyncStatus status = crypto_config_->channel_id_source()->GetChannelIDKey(
      cs->server_id_.host(), &cs->channel_id_key_, channel_id_source_callback);

  switch (status) {
    case QUIC_PENDING:
      cs->channel_id_source_callback_ = channel_id_source_callback;
      QUIC_DVLOG(1) << "Looking up channel ID";
      break;
    case QUIC_FAILURE:
      cs->next_state_ = STATE_NONE;
      delete channel_id_source_callback;
      CloseConnectionWithDetails(QUIC_INVALID_CHANNEL_ID_SIGNATURE,
                                 "Channel ID lookup failed");
      break;
    case QUIC_SUCCESS:
      delete channel_id_source_callback;
      break;
  }
  return status;
}

void QuicCryptoClientStream::DoGetChannelIDComplete(
    QuicCryptoClientStreamConnectionState* cs) {
  if (!cs->channel_id_key_.get()) {
    cs->next_state_ = STATE_NONE;
    CloseConnectionWithDetails(QUIC_INVALID_CHANNEL_ID_SIGNATURE,
                               "Channel ID lookup failed");
    return;
  }
  cs->next_state_ = STATE_SEND_CHLO;
}

void QuicCryptoClientStream::DoReceiveSHLO(
    QuicCryptoClientStreamConnectionState* cs,
    const CryptoHandshakeMessage* in,
    QuicCryptoClientConfig::CachedState* cached) {
  cs->next_state_ = STATE_NONE;
  // We sent a CHLO that we expected to be accepted and now we're
  // hoping for a SHLO from the server to confirm that.  First check
  // to see whether the response was a reject, and if so, move on to
  // the reject-processing state.
  if ((in->tag() == kREJ) || (in->tag() == kSREJ)) {
    // alternative_decrypter will be nullptr if the original alternative
    // decrypter latched and became the primary decrypter. That happens
    // if we received a message encrypted with the INITIAL key.
    if (cs->Connection()->alternative_decrypter() == nullptr) {
      // The rejection was sent encrypted!
      CloseConnectionWithDetails(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT,
                                 "encrypted REJ message");
      return;
    }
    cs->next_state_ = STATE_RECV_REJ;
    return;
  }

  if (in->tag() != kSHLO) {
    CloseConnectionWithDetails(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                               "Expected SHLO or REJ");
    return;
  }

  // alternative_decrypter will be nullptr if the original alternative
  // decrypter latched and became the primary decrypter. That happens
  // if we received a message encrypted with the INITIAL key.
  if (cs->Connection()->alternative_decrypter() != nullptr) {
    // The server hello was sent without encryption.
    CloseConnectionWithDetails(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT,
                               "unencrypted SHLO message");
    return;
  }

  string error_details;
  QuicErrorCode error = crypto_config_->ProcessServerHello(
      *in, cs->Connection()->connection_id(),
      cs->Connection()->version(),
      cs->Connection()->server_supported_versions(), cached,
      cs->crypto_negotiated_params_, &error_details);

  if (error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(error, "Server hello invalid: " + error_details);
    return;
  }
  error = session()->config()->ProcessPeerHello(*in, SERVER, &error_details);
  if (error != QUIC_NO_ERROR) {
    CloseConnectionWithDetails(error, "Server hello invalid: " + error_details);
    return;
  }
  session()->OnConfigNegotiated(cs->Connection());

  CrypterPair* crypters = &cs->crypto_negotiated_params_->forward_secure_crypters;
  // TODO(agl): we don't currently latch this decrypter because the idea
  // has been floated that the server shouldn't send packets encrypted
  // with the FORWARD_SECURE key until it receives a FORWARD_SECURE
  // packet from the client.
  cs->Connection()->SetAlternativeDecrypter(
      ENCRYPTION_FORWARD_SECURE, crypters->decrypter.release(),
      false /* don't latch */);
  cs->Connection()->SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                                        crypters->encrypter.release());
  cs->Connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  cs->handshake_confirmed_ = true;
  session()->OnCryptoHandshakeEvent(cs->Connection(), QuicSession::HANDSHAKE_CONFIRMED);
  cs->Connection()->OnHandshakeComplete();
}

void QuicCryptoClientStream::DoInitializeServerConfigUpdate(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  bool update_ignored = false;
  if (!cached->IsEmpty() && !cached->signature().empty()) {
    // Note that we verify the proof even if the cached proof is valid.
    DCHECK(crypto_config_->proof_verifier());
    cs->next_state_ = STATE_VERIFY_PROOF;
  } else {
    update_ignored = true;
    cs->next_state_ = STATE_NONE;
  }
  UMA_HISTOGRAM_COUNTS("Net.QuicNumServerConfig.UpdateMessagesIgnored",
                       update_ignored);
}

void QuicCryptoClientStream::SetCachedProofValid(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  cached->SetProofValid();
  cs->proof_handler_->OnProofValid(*cached);
}

bool QuicCryptoClientStream::RequiresChannelID(
    QuicCryptoClientStreamConnectionState* cs,
    QuicCryptoClientConfig::CachedState* cached) {
  if (cs->server_id_.privacy_mode() == PRIVACY_MODE_ENABLED ||
      !crypto_config_->channel_id_source()) {
    return false;
  }
  const CryptoHandshakeMessage* scfg = cached->GetServerConfig();
  if (!scfg) {  // scfg may be null then we send an inchoate CHLO.
    return false;
  }
  const QuicTag* their_proof_demands;
  size_t num_their_proof_demands;
  if (scfg->GetTaglist(kPDMD, &their_proof_demands, &num_their_proof_demands) !=
      QUIC_NO_ERROR) {
    return false;
  }
  for (size_t i = 0; i < num_their_proof_demands; i++) {
    if (their_proof_demands[i] == kCHID) {
      return true;
    }
  }
  return false;
}

}  // namespace net
