// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_CRYPTO_STREAM_H_
#define NET_QUIC_CORE_QUIC_CRYPTO_STREAM_H_

#include <cstddef>

#include "base/macros.h"
#include "net/quic/core/crypto/crypto_framer.h"
#include "net/quic/core/crypto/crypto_utils.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_string_piece.h"


namespace net {

class CryptoHandshakeMessage;
class QuicSession;

// Crypto handshake messages in QUIC take place over a reserved stream with the
// id 1.  Each endpoint (client and server) will allocate an instance of a
// subclass of QuicCryptoStream to send and receive handshake messages.  (In the
// normal 1-RTT handshake, the client will send a client hello, CHLO, message.
// The server will receive this message and respond with a server hello message,
// SHLO.  At this point both sides will have established a crypto context they
// can use to send encrypted messages.
//
// For more details:
// https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g/edit?usp=sharing
class QUIC_EXPORT_PRIVATE QuicCryptoStream
    : public QuicStream,
      public CryptoFramerVisitorInterface {
 public:
      explicit QuicCryptoStream(QuicSession* session);
      explicit QuicCryptoStream(QuicSession* session, QuicConnection* connection);

  ~QuicCryptoStream() override;

  // Initiate sending handshake messages to establish a secure connection.
  // Returns true if the session is still connected.
  virtual bool CryptoConnect(QuicConnection* connection);

  // Returns the per-packet framing overhead associated with sending a
  // handshake message for |version|.
  static QuicByteCount CryptoMessageFramingOverhead(QuicVersion version);

  // CryptoFramerVisitorInterface implementation
  void OnError(CryptoFramer* framer) override;
  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override;

  // QuicStream implementation
  void OnDataAvailable() override;

  // Sends |message| to the peer.
  // TODO(wtc): return a success/failure status.
  void SendHandshakeMessage(const CryptoHandshakeMessage& message);

  // Performs key extraction to derive a new secret of |result_len| bytes
  // dependent on |label|, |context|, and the stream's negotiated subkey secret.
  // Returns false if the handshake has not been confirmed or the parameters are
  // invalid (e.g. |label| contains null bytes); returns true on success.
  bool ExportKeyingMaterial(QuicStringPiece label,
                            QuicStringPiece context,
                            size_t result_len,
                            std::string* result) const;

  // Performs key extraction for Token Binding. Unlike ExportKeyingMaterial,
  // this function can be called before forward-secure encryption is
  // established. Returns false if initial encryption has not been established,
  // and true on success.
  //
  // Since this depends only on the initial keys, a signature over it can be
  // repurposed by an attacker who obtains the client's or server's DH private
  // value.
  bool ExportTokenBindingKeyingMaterial(std::string* result) const;

  const QuicCryptoNegotiatedParameters& crypto_negotiated_params() const;

  // Returns true if the encryption is already established on a
  // subflow. If the connection is the nullptr, this function returns
  // true if any subflow has established the encryption.
  bool encryption_established(QuicConnection* connection) const;

  // Returns true if the handshake is already confirmed. If the connection
  // is the nullptr, this function returns true if any subflow has established
  // the encryption.
  bool handshake_confirmed(QuicConnection* connection) const;

 protected:
  class QUIC_EXPORT_PRIVATE QuicCryptoStreamConnectionState {
  public:
    QuicCryptoStreamConnectionState(QuicConnection* connection);
    virtual ~QuicCryptoStreamConnectionState();

    bool encryption_established() const { return encryption_established_; }
    bool handshake_confirmed() const { return handshake_confirmed_; }
    QuicConnection* Connection() { return connection_; }

    bool encryption_established_;
    bool handshake_confirmed_;

    QuicReferenceCountedPointer<QuicCryptoNegotiatedParameters>
        crypto_negotiated_params_;

  private:
    QuicConnection* connection_;
  };

  void AddConnectionState(QuicConnection* connection,
      QuicCryptoStreamConnectionState* connection_state) {
    QUIC_LOG(INFO) << "Adding state for connection " << (long long)connection;
    connection_states_.insert(
        std::pair<QuicConnection*, std::unique_ptr<QuicCryptoStreamConnectionState> >(
            connection,
            std::unique_ptr<QuicCryptoStreamConnectionState>(connection_state)));
  }

  // Returns the QuicCryptoStreamConnectionState object corresponding to connection
  // or nullptr if there is no object.
  QuicCryptoStreamConnectionState* GetConnectionState(const QuicConnection* connection) const {
    auto it = connection_states_.find(const_cast<QuicConnection*>(connection));
    if(it == connection_states_.end()) {
      return nullptr;
    } else {
      return it->second.get();
    }
  }

  bool HasConnectionState(QuicConnection* connection) const {
    return connection_states_.find(connection) != connection_states_.end();
  }

  // Get the connection state of the initial connection/subflow.
  // This is only used for functions that do not use multipathing
  // and cannot be removed from the build due to dependencies.
  QuicCryptoStreamConnectionState* GetInitialConnectionState() const {
    DCHECK(false);
    return nullptr;
  }

  std::map<QuicConnection*, std::unique_ptr<QuicCryptoStreamConnectionState> > connection_states_;

 private:
  CryptoFramer crypto_framer_;

  DISALLOW_COPY_AND_ASSIGN(QuicCryptoStream);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_CRYPTO_STREAM_H_
