(ns clj-nproxy.plugin.tls13.cipher
  (:require [clj-nproxy.bytes :as b])
  (:import [java.security Signature]
           [java.security.spec AlgorithmParameterSpec]
           [javax.crypto Mac KDF Cipher]
           [javax.crypto.spec SecretKeySpec HKDFParameterSpec IvParameterSpec GCMParameterSpec]))

(set! clojure.core/*warn-on-reflection* true)

;;; hmac

(defn hmac
  ^bytes [algo ^bytes key ^bytes data]
  (let [mac (doto (Mac/getInstance algo)
              (.init (SecretKeySpec. key algo)))]
    (.doFinal mac data)))

(def hmac-sha256 (partial hmac "HMACSHA256"))
(def hmac-sha384 (partial hmac "HMACSHA384"))

^:rct/test
(comment
  (b/bytes->hex (hmac-sha256 (.getBytes "hello") (.getBytes "world"))) ; => "f1ac9702eb5faf23ca291a4dc46deddeee2a78ccdaf0a412bed7714cfffb1cc4"
  (b/bytes->hex (hmac-sha384 (.getBytes "hello") (.getBytes "world"))) ; => "80d036d9974e6f71ceabe493ee897d00235edcc4c72e046ddfc8bf68e86a477d63b9f7d26ad5b990aae6ac17db57ddcf"
  )

;;; hkdf

(defn hkdf-extract
  ^bytes [algo ^bytes ikm ^bytes salt]
  (let [kdf (KDF/getInstance algo)
        params (-> (HKDFParameterSpec/ofExtract)
                   (.addIKM ikm)
                   (.addSalt salt)
                   (.extractOnly))]
    (.deriveData kdf params)))

(defn hkdf-expand
  ^bytes [algo ^bytes prk ^bytes info length]
  (let [kdf (KDF/getInstance algo)
        params (HKDFParameterSpec/expandOnly (SecretKeySpec. prk algo) (bytes info) (int length))]
    (.deriveData kdf params)))

(defn hkdf
  ^bytes [algo ^bytes ikm ^bytes salt ^bytes info length]
  (let [kdf (KDF/getInstance algo)
        params (-> (HKDFParameterSpec/ofExtract)
                   (.addIKM ikm)
                   (.addSalt salt)
                   (.thenExpand info length))]
    (.deriveData kdf params)))

(def hkdf-extract-sha256 (partial hkdf-extract "HKDF-SHA256"))
(def hkdf-extract-sha384 (partial hkdf-extract "HKDF-SHA384"))
(def hkdf-expand-sha256 (partial hkdf-expand "HKDF-SHA256"))
(def hkdf-expand-sha384 (partial hkdf-expand "HKDF-SHA384"))
(def hkdf-sha256 (partial hkdf "HKDF-SHA256"))
(def hkdf-sha384 (partial hkdf "HKDF-SHA384"))

^:rct/test
(comment
  (b/bytes->hex (hkdf-sha256 (.getBytes "hello") (.getBytes "world") (.getBytes "info") 16)) ; => "67b45533c1158431eb5176fc56fd0fb7"
  (b/bytes->hex (hkdf-expand-sha256 (hkdf-extract-sha256 (.getBytes "hello") (.getBytes "world")) (.getBytes "info") 16)) ; => "67b45533c1158431eb5176fc56fd0fb7"
  )

;;; aead

(defn aead-crypt
  ^bytes [mode algo ^bytes key ^AlgorithmParameterSpec params ^bytes data ^bytes aad]
  (let [cipher (doto (Cipher/getInstance algo)
                 (.init (int mode) (SecretKeySpec. key algo) params))]
    (when (some? aad)
      (.updateAAD cipher aad))
    (.doFinal cipher data)))

(defn aes-gcm-encrypt [key iv data aad] (aead-crypt Cipher/ENCRYPT_MODE "AES/GCM/NoPadding" key (GCMParameterSpec. 128 iv) data aad))
(defn aes-gcm-decrypt [key iv data aad] (aead-crypt Cipher/DECRYPT_MODE "AES/GCM/NoPadding" key (GCMParameterSpec. 128 iv) data aad))
(defn chacha20-poly1305-encrypt [key iv data aad] (aead-crypt Cipher/ENCRYPT_MODE "ChaCha20-Poly1305" key (IvParameterSpec. iv) data aad))
(defn chacha20-poly1305-decrypt [key iv data aad] (aead-crypt Cipher/DECRYPT_MODE "ChaCha20-Poly1305" key (IvParameterSpec. iv) data aad))

;;; suites

(def aes-128-gcm-sha256-suite
  {:digest-fn b/sha256
   :digest-block-size 64
   :digest-size 32
   :hmac-fn hmac-sha256
   :hkdf-fn hkdf-sha256
   :hkdf-expand-fn hkdf-expand-sha256
   :hkdf-extract-fn hkdf-extract-sha256
   :aead-encrypt-fn aes-gcm-encrypt
   :aead-decrypt-fn aes-gcm-decrypt
   :aead-key-size 16
   :aead-iv-size 12
   :aead-tag-size 16})

(def aes-256-gcm-sha384-suite
  {:digest-fn b/sha384
   :digest-block-size 128
   :digest-size 48
   :hmac-fn hmac-sha384
   :hkdf-fn hkdf-sha384
   :hkdf-expand-fn hkdf-expand-sha384
   :hkdf-extract-fn hkdf-extract-sha384
   :aead-encrypt-fn aes-gcm-encrypt
   :aead-decrypt-fn aes-gcm-decrypt
   :aead-key-size 32
   :aead-iv-size 12
   :aead-tag-size 16})

(def chacha20-poly1305-sha256-suite
  {:digest-fn b/sha256
   :digest-block-size 64
   :digest-size 32
   :hmac-fn hmac-sha256
   :hkdf-fn hkdf-sha256
   :hkdf-expand-fn hkdf-expand-sha256
   :hkdf-extract-fn hkdf-extract-sha256
   :aead-encrypt-fn chacha20-poly1305-encrypt
   :aead-decrypt-fn chacha20-poly1305-decrypt
   :aead-key-size 16
   :aead-iv-size 12
   :aead-tag-size 16})

(def suite-map
  {:tls-aes-128-gcm-sha256       aes-128-gcm-sha256-suite
   :tls-aes-256-gcm-sha384       aes-256-gcm-sha384-suite
   :tls-chacha20-poly1305-sha256 chacha20-poly1305-sha256-suite})
