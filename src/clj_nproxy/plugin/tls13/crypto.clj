(ns clj-nproxy.plugin.tls13.crypto
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto.ecformat :as ecformat])
  (:import [java.io ByteArrayInputStream]
           [java.security.cert Certificate CertificateFactory]))

(set! clojure.core/*warn-on-reflection* true)

(defn mask-bytes-inplace
  "Mask bytes one by one inplace."
  [^bytes b1 ^bytes b2]
  (let [b1 (bytes b1)
        b2 (bytes b2)]
    (dotimes [idx (alength b1)]
      (aset b1 idx (unchecked-byte (bit-xor (aget b1 idx) (aget b2 idx)))))))

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

(defn get-cipher-suite
  "Get cipher suite."
  [cipher-suite]
  (or (get cipher-suite-map cipher-suite)
      (throw (ex-info "invalid cipher suite" {:reason ::invalid-cipher-suite :cipher-suite cipher-suite}))))

(defn digest-size
  "Get digest size."
  [cipher-suite]
  (:digest-size (get-cipher-suite cipher-suite)))

(defn digest
  "Message digest."
  ^bytes [cipher-suite & bs]
  (let [{:keys [digest-fn]} (get-cipher-suite cipher-suite)]
    (apply digest-fn bs)))

(defn hmac
  "Hmac."
  ^bytes [cipher-suite ^bytes key & bs]
  (let [{:keys [hmac-fn]} (get-cipher-suite cipher-suite)]
    (apply hmac-fn key bs)))

(defn hkdf-extract
  "Hkdf extract."
  ^bytes [cipher-suite ^bytes ikm ^bytes salt]
  (let [{:keys [hkdf-extract-fn]} (get-cipher-suite cipher-suite)]
    (hkdf-extract-fn ikm salt)))

(defn hkdf-expand
  "Hkdf expand."
  ^bytes [cipher-suite ^bytes prk ^bytes info ^long length]
  (let [{:keys [hkdf-expand-fn]} (get-cipher-suite cipher-suite)]
    (hkdf-expand-fn prk info length)))

(defn hkdf
  "Hkdf."
  ^bytes [cipher-suite ^bytes ikm ^bytes salt ^bytes info ^Long length]
  (let [{:keys [hkdf-fn]} (get-cipher-suite cipher-suite)]
    (hkdf-fn ikm salt info length)))

(def st-hkdf-label
  (st/keys
   :length st/st-ushort-be
   :label (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str)
   :context (st/->st-var-bytes st/st-ubyte)))

(defn hkdf-expand-label
  "Hkdf expand label."
  ^bytes [cipher-suite ^bytes secret ^String label ^bytes context ^Long length]
  (let [info (st/pack st-hkdf-label length label context)]
    (hkdf-expand cipher-suite secret info length)))

;;; cryptor

(defn ->cryptor
  "Construct cryptor."
  [cipher-suite ^bytes secret]
  (let [{:keys [aead-key-size aead-iv-size]} (get-cipher-suite cipher-suite)
        key (hkdf-expand-label cipher-suite secret tls13-st/label-key (byte-array 0) aead-key-size)
        iv (hkdf-expand-label cipher-suite secret tls13-st/label-iv (byte-array 0) aead-iv-size)]
    {:cipher-suite cipher-suite :key key :iv iv :sequence sequence}))

(defn aead-tag-size
  "Get aead tag size."
  [cryptor]
  (let [{:keys [cipher-suite]} cryptor]
    (:aead-tag-size (get-cipher-suite cipher-suite))))

(defn sequenced-iv
  "Get seqneuced iv."
  [cryptor]
  (let [{:keys [sequence iv]} cryptor]
    (doto (b/right-align (st/pack-long-be sequence) (b/length iv))
      (mask-bytes-inplace iv))))

(defn encrypt
  "Encrypt data, return new cryptor and encrypted data."
  [cryptor ^bytes data & [^bytes aad]]
  (let [{:keys [cipher-suite key]} cryptor
        {:keys [aead-encrypt-fn]} (get-cipher-suite cipher-suite)]
    [(update cryptor :sequence inc)
     (aead-encrypt-fn key (sequenced-iv cryptor) aad)]))

(defn decrypt
  "Decrypt data, return new cryptor and decrypted data."
  [cryptor ^bytes data & [^bytes aad]]
  (let [{:keys [key cipher-suite]} cryptor
        {:keys [aead-decrypt-fn]} (get-cipher-suite cipher-suite)]
    [(update cryptor :sequence inc)
     (aead-decrypt-fn key (sequenced-iv cryptor) aad)]))

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

(defn get-named-group
  [named-group]
  (or (get named-group-map named-group)
      (throw (ex-info "invalid named group" {:reason ::invalid-named-group :named-group named-group}))))

(defn gen-key-share
  "Generate key share from named group."
  [named-group]
  (let [{:keys [gen-fn]} (get-named-group named-group)
        [pri pub] (gen-fn)]
    {:named-group named-group :pri pri :pub pub}))

(defn key-share->pub-bytes
  "Convert key share to pub."
  ^bytes [key-share]
  (let [{:keys [named-group pub]} key-share
        {:keys [pub->bytes-fn]} (get-named-group named-group)]
    (pub->bytes-fn pub)))

(defn key-agreement
  "Key agreement."
  ^bytes [key-share ^bytes pub-bytes]
  (let [{:keys [named-group pri]} key-share
        {:keys [agreement-fn bytes->pub-fn]} (get-named-group named-group)
        pub (bytes->pub-fn pub-bytes)]
    (agreement-fn pri pub)))

;;; cert

(defn cert->bytes
  "Convert certificate to bytes."
  ^bytes [^Certificate cert]
  (.getEncoded cert))

(defn bytes->cert
  "Convert bytes to certificate."
  ^Certificate [^bytes b]
  (let [cf (CertificateFactory/getInstance "X509")]
    (with-open [is (ByteArrayInputStream. b)]
      (let [cert (.generateCertificate cf is)]
        (if (zero? (.available is))
          cert
          (throw (ex-info "certificate surplus" {:reason ::certificate-surplus})))))))
