(ns clj-nproxy.plugin.tls13.context
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto :as tls13-crypto]))

(def vec-conj (fnil conj []))

(defn mask-bytes-inplace
  "Mask bytes one by one inplace."
  [^bytes b1 ^bytes b2]
  (let [b1 (bytes b1)
        b2 (bytes b2)]
    (dotimes [idx (alength b1)]
      (aset b1 idx (unchecked-byte (bit-xor (aget b1 idx) (aget b2 idx)))))))

;;; crypto

;;;; cipher suite

(defn digest
  "Message digest."
  ^bytes [cipher-suite & bs]
  (let [{:keys [digest-fn]} cipher-suite]
    (apply digest-fn bs)))

(defn hmac
  "Hmac."
  ^bytes [cipher-suite ^bytes key & bs]
  (let [{:keys [hmac-fn]} cipher-suite]
    (apply hmac-fn key bs)))

(defn hkdf-extract
  "Hkdf extract."
  ^bytes [cipher-suite ^bytes ikm ^bytes salt]
  (let [{:keys [hkdf-extract-fn]} cipher-suite]
    (hkdf-extract-fn ikm salt)))

(defn hkdf-expand
  "Hkdf expand."
  ^bytes [cipher-suite ^bytes prk ^bytes info ^long length]
  (let [{:keys [hkdf-expand-fn]} cipher-suite]
    (hkdf-expand-fn prk info length)))

(defn hkdf
  "Hkdf."
  ^bytes [cipher-suite ^bytes ikm ^bytes salt ^bytes info ^Long length]
  (let [{:keys [hkdf-fn]} cipher-suite]
    (hkdf-fn ikm salt info length)))

;;;; key schedule

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

(defn derive-secret
  "Derive secret."
  ^bytes [cipher-suite ^bytes secret ^String label msgs]
  (let [{:keys [digest-size]} cipher-suite
        context (apply digest cipher-suite msgs)]
    (hkdf-expand-label cipher-suite secret label context digest-size)))

(defn early-secret
  (^bytes [cipher-suite]
   (let [{:keys [digest-size]} cipher-suite]
     (early-secret cipher-suite (byte-array digest-size))))
  (^bytes [cipher-suite ^bytes psk]
   (let [{:keys [digest-size]} cipher-suite]
     (hkdf-extract cipher-suite psk (byte-array digest-size)))))

(defn handshake-secret
  ^bytes [cipher-suite ^bytes early-secret ^bytes shared-secret]
  (let [derived (derive-secret cipher-suite early-secret tls13-st/label-derived nil)]
    (hkdf-extract cipher-suite shared-secret derived)))

;; client hello ... server hello
(defn client-handshake-secret
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (derive-secret cipher-suite handshake-secret tls13-st/label-client-handshake msgs))

;; client hello ... server hello
(defn server-handshake-secret
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (derive-secret cipher-suite handshake-secret tls13-st/label-server-handshake msgs))

(defn master-secret
  ^bytes [cipher-suite ^bytes handshake-secret]
  (let [{:keys [digest-size]} cipher-suite
        derived (derive-secret cipher-suite handshake-secret tls13-st/label-derived nil)]
    (hkdf-extract cipher-suite (byte-array digest-size) derived)))

;; client hello ... server finished
(defn client-application-secret
  ^bytes [cipher-suite ^bytes master-secret msgs]
  (derive-secret cipher-suite master-secret tls13-st/label-client-application msgs))

;; client hello ... server finished
(defn server-application-secret
  ^bytes [cipher-suite ^bytes master-secret msgs]
  (derive-secret cipher-suite master-secret tls13-st/label-server-application msgs))

;;;; cryptor

(defn ->cryptor
  "Construct cryptor."
  [cipher-suite ^bytes secret]
  (let [{:keys [aead-key-size aead-iv-size]} cipher-suite
        key (hkdf-expand-label cipher-suite secret tls13-st/label-key (byte-array 0) aead-key-size)
        iv (hkdf-expand-label cipher-suite secret tls13-st/label-iv (byte-array 0) aead-iv-size)]
    (merge cipher-suite {:key key :iv iv :sequence sequence})))

(defn sequenced-iv
  "Get seqneuced iv."
  [cryptor]
  (let [{:keys [sequence iv]} cryptor]
    (doto (b/right-align (st/pack-long-be sequence) (b/length iv))
      (mask-bytes-inplace iv))))

(defn encrypt
  "Encrypt data, return new cryptor and encrypted data."
  [cryptor ^bytes data & [^bytes aad]]
  (let [{:keys [key aead-encrypt-fn]} cryptor]
    [(update cryptor :sequence inc)
     (aead-encrypt-fn key (sequenced-iv cryptor) aad)]))

(defn decrypt
  "Decrypt data, return new cryptor and decrypted data."
  [cryptor ^bytes data & [^bytes aad]]
  (let [{:keys [key aead-decrypt-fn]} cryptor]
    [(update cryptor :sequence inc)
     (aead-decrypt-fn key (sequenced-iv cryptor) aad)]))

(defn encrypt-record
  "Encrypt record, return new cryptor and ciphertext with header."
  [cryptor type content]
  (let [{:keys [aead-tag-size]} cryptor
        plaintext (tls13-st/pack-inner-plaintext type content)
        header (st/pack tls13-st/st-record-header
                        tls13-st/content-type-application-data
                        tls13-st/version-tls12
                        (+ aead-tag-size (b/length plaintext)))
        [cryptor ciphertext] (encrypt cryptor plaintext header)]
    [cryptor (b/cat header ciphertext)]))

(defn decrypt-record
  "Decrypt record, return new cryptor, type and content."
  [cryptor ciphertext]
  (let [header (st/pack tls13-st/st-record-header
                        tls13-st/content-type-application-data
                        tls13-st/version-tls12
                        (b/length ciphertext))
        [cryptor plaintext] (decrypt cryptor ciphertext header)
        [type content] (tls13-st/unpack-inner-plaintext plaintext)]
    [cryptor type content]))

;;;; key share

(defn ->key-share
  "Construct key share."
  [named-group]
  (let [{:keys [gen-fn] :as group} (get tls13-crypto/named-group-map named-group)
        [pri pub] (gen-fn)]
    (merge group {:pri pri :pub pub})))

(defn key-share-pub-data
  "Get public key data."
  ^bytes [key-share]
  (let [{:keys [pub pub->bytes-fn]} key-share]
    (pub->bytes-fn pub)))

(defn key-agreement
  "Key agreement."
  ^bytes [key-share ^bytes pub-data]
  (let [{:keys [pri bytes->pub-fn key-agreement-fn]} key-share]
    (key-agreement-fn pri (bytes->pub-fn pub-data))))

;;; context

;; stage: wait-sh wait-ccs-ee wait-ee wait-cert wait-cv wait-finished connected

(declare pack-client-extensions)
(declare send-client-hello)

(def default-signature-algorithms
  [tls13-st/signature-scheme-ed25519
   tls13-st/signature-scheme-ed448
   tls13-st/signature-scheme-ecdsa-secp256r1-sha256
   tls13-st/signature-scheme-ecdsa-secp384r1-sha384
   tls13-st/signature-scheme-ecdsa-secp521r1-sha512])

(def default-cipher-suites
  [tls13-st/cipher-suite-tls-aes-128-gcm-sha256
   tls13-st/cipher-suite-tls-aes-256-gcm-sha384
   tls13-st/cipher-suite-tls-chacha20-poly1305-sha256])

(def default-named-groups
  [tls13-st/named-group-x25519])

(defn init-context
  "Construct init context."
  [{:keys [supported-signature-algorithms supported-cipher-suites supported-named-groups
           server-names application-protocols]
    :or {supported-signature-algorithms default-signature-algorithms
         supported-cipher-suites default-cipher-suites
         supported-named-groups default-named-groups}}]
  (let [client-random (b/rand 32)
        key-shares (->> supported-named-groups (mapv ->key-share))]
    (-> {:stage :wait-sh
         :signature-algorithms supported-signature-algorithms
         :supported-cipher-suites supported-cipher-suites
         :named-groups supported-named-groups
         :server-names server-names
         :application-protocols application-protocols
         :client-random client-random
         :key-shares key-shares}
        pack-client-extensions
        send-client-hello)))

(defn send-plaintext
  "Send plaintext."
  [context type content]
  (let [record (st/pack tls13-st/st-record {:type type :version tls13-st/version-tls12 :content content})]
    (update :send-bytes vec-conj record)))

(defn send-ciphertext
  "Send ciphertext."
  [context encryptor-key type content]
  (let [encryptor (get context encryptor-key)
        [encryptor record] (encrypt-record encryptor type content)]
    (-> context
        (assoc encryptor-key encryptor)
        (update :send-bytes vec-conj record))))

(defn recv-ciphertext
  "Recv ciphertext, return new context and decrypted type, content."
  [context decryptor-key content]
  (let [decryptor (get context decryptor-key)
        [decryptor type content] (decrypt-record decryptor content)
        context (assoc context decryptor-key decryptor)]
    [context type content]))

(defn send-handshake-plaintext
  "Send handshake plaintext."
  [context msg-type msg-data]
  (let [handshake (st/pack tls13-st/st-handshake {:msg-type msg-type :msg-data msg-data})]
    (-> context
        (update :handshake-msgs vec-conj handshake)
        (send-plaintext tls13-st/content-type-handshake handshake))))

(defn send-handshake-ciphertext
  "Send handshake ciphertext."
  [context msg-type msg-data]
  (let [handshake (st/pack tls13-st/st-handshake {:msg-type msg-type :msg-data msg-data})]
    (-> context
        (update :handshake-msgs vec-conj handshake)
        (send-ciphertext :handshake-encryptor tls13-st/content-type-handshake handshake))))

(defn recv-handshake-plaintext
  "Recv handshake plaintext, return new context, msg type and msg data."
  ([context type content]
   (case type
     tls13-st/content-type-handshake
     (recv-handshake-plaintext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (let [context (update context :handshake-msgs vec-conj content)
         {:keys [msg-type msg-data]} (st/unpack tls13-st/st-handshake content)]
     [context msg-type msg-data])))

(defn recv-handshake-ciphertext
  "Recv handshake ciphertext, return new context, msg type and msg data."
  ([context type content]
   (case type
     tls13-st/content-type-application-data
     (recv-handshake-ciphertext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (let [[context type content] (recv-ciphertext context :handshake-decryptor content)]
     (recv-handshake-plaintext context type content))))

(defn send-application-ciphertext
  "Send application ciphertext."
  [context type content]
  (send-ciphertext context :application-encryptor type content))

(defn recv-application-ciphertext
  "Recv application ciphertext."
  [context content]
  (recv-ciphertext context :application-decryptor type content))

(defn send-change-cipher-spec
  [context]
  (send-plaintext
   context
   tls13-st/content-type-change-cipher-spec
   (st/pack tls13-st/st-change-cipher-spec tls13-st/change-ciper-spec)))

(defn pack-client-extension
  [context type extension]
  (update context :client-extensions vec-conj [type extension]))

(defn pack-client-extension-supported-versions
  [context]
  (pack-client-extension
   context
   tls13-st/extension-type-supported-versions
   (st/pack tls13-st/st-extension-supported-version-client-hello [tls13-st/version-tls13])))

(defn pack-client-extension-signature-algorithms
  [{:keys [supported-signature-algorithms] :as context}]
  (pack-client-extension
   context
   tls13-st/extension-type-signature-algorithms
   (st/pack tls13-st/st-extension-signature-algorithms supported-signature-algorithms)))

(defn pack-client-extension-supported-groups
  [{:keys [supported-named-groups] :as context}]
  (pack-client-extension
   context
   tls13-st/extension-type-supported-groups
   (st/pack tls13-st/st-extension-supported-groups supported-named-groups)))

(defn pack-client-extension-key-share
  [{:keys [supported-groups key-shares] :as context}]
  (pack-client-extension
   context
   tls13-st/extension-type-key-share
   (st/pack tls13-st/st-extension-key-share-client-hello
            (map
             (fn [named-group key-share]
               {:named-group named-group :key-exchange (key-share-pub-data key-share)})
             supported-groups key-shares))))

(defn pack-client-extension-server-name
  [{:keys [server-names] :as context}]
  (cond-> context
    (seq server-names)
    (pack-client-extension
     tls13-st/extension-type-server-name
     (st/pack tls13-st/st-extension-server-name-client-hello
              (->> server-names
                   (map
                    (fn [server-name]
                      {:name-type 0 :name server-name})))))))

(defn pack-client-extension-application-layer-protocol-negotiation
  [{:keys [application-protocols] :as context}]
  (cond-> context
    (seq application-protocols)
    (pack-client-extension
     tls13-st/extension-type-application-layer-protocol-negotiation
     (st/pack tls13-st/st-extension-application-layer-protocol-negotiation application-protocols))))

(defn pack-client-extensions
  [context]
  (-> context
      pack-client-extension-supported-versions
      pack-client-extension-signature-algorithms
      pack-client-extension-supported-groups
      pack-client-extension-key-share
      pack-client-extension-server-name
      pack-client-extension-application-layer-protocol-negotiation))

(defn send-client-hello
  "Second client hello."
  [context]
  (let [{:keys [client-random supported-cipher-suites client-extensions]} context]
    (send-handshake-plaintext
     context
     tls13-st/handshake-type-client-hello
     (st/pack tls13-st/st-handshake-client-hello
              {:legacy-version tls13-st/version-tls12
               :random client-random
               :legacy-session-id (byte-array 0)
               :cipher-suites supported-cipher-suites
               :legacy-compression-methods [tls13-st/compression-method-null]
               :extensions client-extensions}))))

(defmulti recv-record
  "Recv record, return new context."
  (fn [context _type _content] (:stage context)))

(defn init-cipher-suite
  [{:keys [supported-cipher-suites selected-cipher-suite] :as context}]
  (if (contains? (set supported-cipher-suites) selected-cipher-suite)
    (let [cipher-suite (get tls13-crypto/cipher-suite-map selected-cipher-suite)
          early-secret (early-secret cipher-suite)]
      (assoc context :cipher-suite cipher-suite :early-secret early-secret))
    (throw (ex-info "invalid cipher suite" {:reason ::invalid-cipher-suite :cipher-suite selected-cipher-suite}))))

(defn unpack-server-extension-supported-versions
  [{:keys [server-extensions] :as context}]
  (if-let [[_ extension] (->> server-extensions
                              (filter #(= tls13-st/extension-type-supported-versions (first %)))
                              first)]
    (let [selected-version (st/unpack tls13-st/st-extension-supported-version-server-hello extension)]
      (if (= selected-version tls13-st/version-tls13)
        context
        (throw (ex-info "invalid version" {:reason ::invalid-version :version selected-version}))))
    (throw (ex-info "no selected version" {:reason ::no-selected-version}))))

(defn init-handshake-secret
  [{:keys [cipher-suite early-secret shared-secret handshake-msgs] :as context}]
  (let [{:keys [digest-size]} cipher-suite
        handshake-secret (handshake-secret cipher-suite early-secret shared-secret)
        client-handshake-secret (client-handshake-secret cipher-suite handshake-msgs)
        server-handshake-secret (server-handshake-secret cipher-suite handshake-msgs)
        client-handshake-verify-key (hkdf-expand-label cipher-suite client-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        server-handshake-verify-key (hkdf-expand-label cipher-suite server-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        handshake-encryptor (->cryptor cipher-suite client-handshake-secret)
        handshake-decryptor (->cryptor cipher-suite server-handshake-secret)]
    (merge
     context
     {:handshake-secret handshake-secret
      :client-handshake-secret client-handshake-secret
      :server-handshake-secret server-handshake-secret
      :client-handshake-verify-key client-handshake-verify-key
      :server-handshake-verify-key server-handshake-verify-key
      :handshake-encryptor handshake-encryptor
      :handshake-decryptor handshake-decryptor})))

(defn unpack-server-extension-key-share
  [{:keys [server-extensions supported-named-groups key-shares] :as context}]
  (if-let [[_ extension] (->> server-extensions
                              (filter #(= tls13-st/extension-type-key-share (first %)))
                              first)]
    (let [{:keys [key-exchange] selected-named-group :group}
          (st/unpack tls13-st/st-extension-key-share-server-hello extension)]
      (if-let [[_ key-share] (->> (map vector supported-named-groups key-shares)
                                  (filter #(= selected-named-group (first %))))]
        (let [shared-secret (key-agreement key-share key-exchange)]
          (-> context
              (merge {:shared-secret shared-secret})
              init-handshake-secret))
        (throw (ex-info "invalid named group" {:reason ::invalid-named-group :named-group selected-named-group}))))
    (throw (ex-info "no selected key share" {:reason ::no-selected-key-share}))))

(defmethod recv-record :wait-sh [context type content]
  (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
    (case msg-type
      tls13-st/handshake-type-server-hello
      (let [{:keys [random cipher-suite extensions]} (st/unpack tls13-st/st-handshake-server-hello msg-data)]
        (-> context
            (merge
             {:stage :wait-ccs-ee
              :selected-cipher-suite cipher-suite
              :server-random random
              :server-extensions extensions})
            init-cipher-suite
            unpack-server-extension-supported-versions
            unpack-server-extension-key-share))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defmethod recv-record :wait-ccs-ee [context type content]
  (case type
    tls13-st/content-type-application-data
    (-> context
        (assoc :stage :wait-ee)
        (recv-record type content))
    tls13-st/content-type-change-cipher-spec
    (let [change-cipher-spec (st/unpack tls13-st/st-change-cipher-spec)]
      (if (= change-cipher-spec tls13-st/change-ciper-spec)
        (assoc context :stage :wait-ee)
        (throw (ex-info "invalid change cipher spec" {:reason ::invalid-change-cipher-spec :change-cipher-spec change-cipher-spec}))))
    (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))

(defn unpack-server-encrypted-extension-application-layer-protocol-negotiation
  [{:keys [application-protocols server-encrypted-extensions] :as context}]
  (if-let [[_ extension] (->> server-encrypted-extensions
                              (filter #(= tls13-st/extension-type-application-layer-protocol-negotiation (first %)))
                              first)]
    (let [selected-protocols (st/unpack tls13-st/st-extension-application-layer-protocol-negotiation extension)]
      (if (= 1 (count selected-protocols))
        (let [selected-protocol (first selected-protocols)]
          (if (contains? (set application-protocols) selected-protocol)
            (assoc context :selected-application-protocol selected-protocol)
            (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :protocols selected-protocols}))))
        (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :protocols selected-protocols}))))
    context))

(defmethod recv-record :wait-ee [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-encrypted-extensions
      (let [extensions (st/unpack tls13-st/st-handshake-encrypted-extension)]
        (-> context
            (merge
             {:stage :wait-cert
              :server-encrypted-extensions extensions})
            unpack-server-encrypted-extension-application-layer-protocol-negotiation))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defmethod recv-record :wait-cert [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-certificate
      (let [{:keys [certificate-request-context certificate-list]}
            (st/unpack tls13-st/st-handshake-certificate)]
        (merge
         context
         {:stage :wait-cv
          :server-certificate-request-context certificate-request-context
          :server-certificate-list certificate-list}))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defmethod recv-record :wait-cv [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-certificate-verify
      (let [{:keys [handshake-msgs]} context
            {:keys [algorithm signature]} (st/unpack tls13-st/st-handshake-certificate-verify)]
        (merge
         context
         {:stage :wait-finished
          :server-signature-algorithm algorithm
          :server-signature signature
          :server-signature-msgs (butlast handshake-msgs)}))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defn verify-server-finished
  [context msg-data]
  (let [{:keys [cipher-suite server-handshake-verify-key handshake-msgs]} context
        verify (hmac cipher-suite
                     server-handshake-verify-key
                     (apply digest cipher-suite (butlast handshake-msgs)))]
    (if (zero? (b/compare msg-data verify))
      context
      (throw (ex-info "invalid finished" {:reason ::invalid-finished})))))

(defn send-client-finished
  [{:keys [cipher-suite client-handshake-verify-key handshake-msgs] :as context}]
  (let [verify (hmac cipher-suite
                     client-handshake-verify-key
                     (apply digest cipher-suite handshake-msgs))]
    (send-handshake-ciphertext context tls13-st/handshake-type-finished verify)))

(defn init-master-secret
  [{:keys [cipher-suite handshake-secret handshake-msgs] :as context}]
  (let [master-secret (master-secret cipher-suite handshake-secret)
        client-application-secret (client-application-secret cipher-suite master-secret handshake-msgs)
        server-application-secret (server-application-secret cipher-suite master-secret handshake-msgs)
        application-encryptor (->cryptor cipher-suite client-application-secret)
        application-decryptor (->cryptor cipher-suite server-application-secret)]
    (merge
     context
     {:master-secret master-secret
      :client-application-secret client-application-secret
      :server-application-secret server-application-secret
      :application-decryptor application-decryptor
      :application-encryptor application-encryptor})))

(defmethod recv-record :wait-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-server-finished msg-data)
          send-change-cipher-spec
          send-client-finished
          init-master-secret)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))
