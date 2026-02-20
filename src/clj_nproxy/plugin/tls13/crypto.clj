(ns clj-nproxy.plugin.tls13.crypto
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto])
  (:import [java.security KeyFactory AlgorithmParameters]
           [java.security.spec ECPoint ECParameterSpec ECGenParameterSpec ECPublicKeySpec XECPublicKeySpec NamedParameterSpec]
           [java.security.interfaces ECPublicKey XECPublicKey]))

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

;;; named groups

(defn left-pad-bytes
  "Left pad bytes."
  ^bytes [^bytes b ^long len]
  (let [plen (- len (b/length b))]
    (cond->> b
      (pos? plen) (b/cat (byte-array plen)))))

(defn right-pad-bytes
  "Right pad bytes."
  ^bytes [^bytes b ^long len]
  (let [plen (- len (b/length b))]
    (cond-> b
      (pos? plen) (b/cat (byte-array plen)))))

^:rct/test
(comment
  (seq (left-pad-bytes (byte-array [1 2 3]) 4)) ; => [0 1 2 3]
  (seq (right-pad-bytes (byte-array [1 2 3]) 4)) ; => [1 2 3 0]
  )

(defn left-cut-bytes
  "Left cut bytes."
  ^bytes [^bytes b ^long len]
  (let [l (b/length b)]
    (if (<= l len)
      b
      (b/copy-of-range b (- l len) l))))

(defn right-cut-bytes
  "Right cut bytes."
  ^bytes [^bytes b ^long len]
  (if (<= (b/length b) len)
    b
    (b/copy-of b len)))

^:rct/test
(comment
  (seq (left-cut-bytes (byte-array [1 2 3]) 2)) ; => [2 3]
  (seq (right-cut-bytes (byte-array [1 2 3]) 2)) ; => [1 2]
  )

(defn reverse-bytes
  "Reverse bytes."
  ^bytes [^bytes b]
  (let [b (bytes b)
        l (alength b)
        nb (byte-array l)]
    (dotimes [i l]
      (aset nb i (aget b (- l i 1))))
    nb))

^:rct/test
(comment
  (seq (reverse-bytes (byte-array [1 2 3]))) ; => [3 2 1]
  )

(defn ec-pub->bytes
  "Convert ec public key to bytes."
  ^bytes [len ^ECPublicKey pub]
  (let [^ECPoint w (.getW pub)
        x (-> (.toByteArray (.getAffineX w)) (left-pad-bytes len) (left-cut-bytes len))
        y (-> (.toByteArray (.getAffineY w)) (left-pad-bytes len) (left-cut-bytes len))]
    (b/cat (byte-array [4]) x y)))

(def secp256r1-pub->bytes (partial ec-pub->bytes 32))
(def secp384r1-pub->bytes (partial ec-pub->bytes 48))
(def secp521r1-pub->bytes (partial ec-pub->bytes 66))

(defn bytes->ec-pub
  "Convert bytes to ec public key."
  ^ECPublicKey [name len ^bytes b]
  (if (and (= (inc (* 2 len)) (alength b)) (= 4 (aget b 0)))
    (let [x (b/copy-of-range b 1 (inc len))
          y (b/copy-of-range b (inc len) (inc (* 2 len)))
          w (ECPoint. (BigInteger. 1 (bytes x)) (BigInteger. 1 (bytes y)))
          params (doto (AlgorithmParameters/getInstance "EC")
                   (.init (ECGenParameterSpec. name)))
          params (.getParameterSpec params ECParameterSpec)
          spec (ECPublicKeySpec. w params)]
      (-> (KeyFactory/getInstance "EC")
          (.generatePublic spec)))
    (throw (st/data-error))))

(def bytes->secp256r1-pub (partial bytes->ec-pub "secp256r1" 32))
(def bytes->secp384r1-pub (partial bytes->ec-pub "secp384r1" 48))
(def bytes->secp521r1-pub (partial bytes->ec-pub "secp521r1" 66))

(defn xec-pub->bytes
  "Convert xec public key to bytes."
  ^bytes [len ^XECPublicKey pub]
  (let [be-bytes (.toByteArray (.getU pub))
        le-bytes (-> be-bytes reverse-bytes (right-pad-bytes len))]
    (if (= len (count le-bytes))
      le-bytes
      (throw (st/data-error)))))

(def x25519-pub->bytes (partial xec-pub->bytes 32))
(def x448-pub->bytes (partial xec-pub->bytes 56))

(defn bytes->xec-pub
  "Convert bytes to xec public key."
  ^XECPublicKey [name ^bytes b]
  (let [spec (XECPublicKeySpec.
              (NamedParameterSpec. name)
              (BigInteger. 1 (reverse-bytes b)))]
    (-> (KeyFactory/getInstance name)
        (.generatePublic spec))))

(def bytes->x25519-pub (partial bytes->xec-pub "X25519"))
(def bytes->x448-pub (partial bytes->xec-pub "X448"))

(def secp256r1-group
  {:gen-fn        crypto/secp256r1-gen
   :agreement-fn  crypto/secp256r1-agreement
   :pub->bytes-fn secp256r1-pub->bytes
   :bytes->pub-fn bytes->secp256r1-pub})

(def secp384r1-group
  {:gen-fn        crypto/secp384r1-gen
   :agreement-fn  crypto/secp384r1-agreement
   :pub->bytes-fn secp384r1-pub->bytes
   :bytes->pub-fn bytes->secp384r1-pub})

(def secp521r1-group
  {:gen-fn        crypto/secp521r1-gen
   :agreement-fn  crypto/secp521r1-agreement
   :pub->bytes-fn secp521r1-pub->bytes
   :bytes->pub-fn bytes->secp521r1-pub})

(def x25519-group
  {:gen-fn        crypto/x25519-gen
   :agreement-fn  crypto/x25519-agreement
   :pub->bytes-fn x25519-pub->bytes
   :bytes->pub-fn bytes->x25519-pub})

(def x448-group
  {:gen-fn        crypto/x448-gen
   :agreement-fn  crypto/x448-agreement
   :pub->bytes-fn x448-pub->bytes
   :bytes->pub-fn bytes->x448-pub})

(def named-group-map
  {0x0017 secp256r1-group
   0x0018 secp384r1-group
   0x0019 secp521r1-group
   0x001d x25519-group
   0x001e x448-group})
