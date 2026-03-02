(ns clj-nproxy.plugin.tls13.crypto
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto.ecformat :as ecformat]))

;;; cipher suites

(def sha256-base-suite
  {:digest-fn       crypto/sha256
   :digest-size     32
   :hmac-fn         crypto/hmac-sha256
   :hkdf-fn         crypto/hkdf-sha256
   :hkdf-expand-fn  crypto/hkdf-expand-sha256
   :hkdf-extract-fn crypto/hkdf-extract-sha256})

(def sha384-base-suite
  {:digest-fn       crypto/sha384
   :digest-size     48
   :hmac-fn         crypto/hmac-sha384
   :hkdf-fn         crypto/hkdf-sha384
   :hkdf-expand-fn  crypto/hkdf-expand-sha384
   :hkdf-extract-fn crypto/hkdf-extract-sha384})

(def aes-128-gcm-sha256-suite
  (merge
   sha256-base-suite
   {:aead-encrypt-fn crypto/aesgcm-encrypt
    :aead-decrypt-fn crypto/aesgcm-decrypt
    :aead-key-size   16
    :aead-iv-size    12
    :aead-tag-size   16}))

(def aes-256-gcm-sha384-suite
  (merge
   sha384-base-suite
   {:aead-encrypt-fn crypto/aesgcm-encrypt
    :aead-decrypt-fn crypto/aesgcm-decrypt
    :aead-key-size   32
    :aead-iv-size    12
    :aead-tag-size   16}))

(def chacha20-poly1305-sha256-suite
  (merge
   sha256-base-suite
   {:aead-encrypt-fn crypto/chacha20poly1305-encrypt
    :aead-decrypt-fn crypto/chacha20poly1305-decrypt
    :aead-key-size   16
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-map
  {tls13-st/cipher-suite-tls-aes-128-gcm-sha256       aes-128-gcm-sha256-suite
   tls13-st/cipher-suite-tls-aes-256-gcm-sha384       aes-256-gcm-sha384-suite
   tls13-st/cipher-suite-tls-chacha20-poly1305-sha256 chacha20-poly1305-sha256-suite})

;;; named groups

(def secp256r1-group
  {:gen-fn        crypto/secp256r1-gen
   :agreement-fn  crypto/secp256r1-agreement
   :pub->bytes-fn ecformat/secp256r1-pub->bytes
   :bytes->pub-fn ecformat/bytes->secp256r1-pub})

(def secp384r1-group
  {:gen-fn        crypto/secp384r1-gen
   :agreement-fn  crypto/secp384r1-agreement
   :pub->bytes-fn ecformat/secp384r1-pub->bytes
   :bytes->pub-fn ecformat/bytes->secp384r1-pub})

(def secp521r1-group
  {:gen-fn        crypto/secp521r1-gen
   :agreement-fn  crypto/secp521r1-agreement
   :pub->bytes-fn ecformat/secp521r1-pub->bytes
   :bytes->pub-fn ecformat/bytes->secp521r1-pub})

(def x25519-group
  {:gen-fn        crypto/x25519-gen
   :agreement-fn  crypto/x25519-agreement
   :pub->bytes-fn ecformat/x25519-pub->bytes
   :bytes->pub-fn ecformat/bytes->x25519-pub})

(def x448-group
  {:gen-fn        crypto/x448-gen
   :agreement-fn  crypto/x448-agreement
   :pub->bytes-fn ecformat/x448-pub->bytes
   :bytes->pub-fn ecformat/bytes->x448-pub})

(def named-group-map
  {tls13-st/named-group-secp256r1 secp256r1-group
   tls13-st/named-group-secp384r1 secp384r1-group
   tls13-st/named-group-secp521r1 secp521r1-group
   tls13-st/named-group-x25519    x25519-group
   tls13-st/named-group-x448      x448-group})

(defn sim-agreement
  "Simulate key agreement."
  [group]
  (let [{:keys [gen-fn agreement-fn pub->bytes-fn bytes->pub-fn]} group
        [pri1 pub1] (gen-fn)
        [pri2 pub2] (gen-fn)]
    (zero?
     (b/compare
      (agreement-fn pri1 (-> pub2 pub->bytes-fn bytes->pub-fn))
      (agreement-fn pri2 (-> pub1 pub->bytes-fn bytes->pub-fn))))))

^:rct/test
(comment
  (sim-agreement secp256r1-group) ; => true
  (sim-agreement secp384r1-group) ; => true
  (sim-agreement secp521r1-group) ; => true
  (sim-agreement x25519-group) ; => true
  (sim-agreement x448-group) ; => true
  )
