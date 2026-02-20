(ns clj-nproxy.plugin.tls13.crypto
  (:require [clj-nproxy.crypto :as crypto]))

(set! clojure.core/*warn-on-reflection* true)

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
  {0x1301 aes-128-gcm-sha256-suite
   0x1302 aes-256-gcm-sha384-suite
   0x1303 chacha20-poly1305-sha256-suite})
