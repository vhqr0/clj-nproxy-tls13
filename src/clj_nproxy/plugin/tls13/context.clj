(ns clj-nproxy.plugin.tls13.context
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto :as tls13-crypto]))

(def vec-conj (fnil conj []))

(defn pack-extension
  "Pack extension."
  [context extensions-key type extension]
  (update context extensions-key vec-conj [type extension]))

(defn find-extension
  "Find extension."
  [context extensions-key type]
  (->> (get context extensions-key) (filter #(= type (first %))) first))

(defn send-plaintext
  "Send plaintext."
  [context type content]
  (let [record (st/pack tls13-st/st-record {:type type :version tls13-st/version-tls12 :content content})]
    (update context :send-bytes vec-conj record)))

(defn encrypt-record
  "Encrypt record, return new cryptor and ciphertext with header."
  [cryptor type content]
  (let [aead-tag-size (tls13-crypto/aead-tag-size cryptor)
        plaintext (tls13-st/pack-inner-plaintext type content)
        header (st/pack tls13-st/st-record-header
                        {:type tls13-st/content-type-application-data
                         :version tls13-st/version-tls12
                         :length (+ aead-tag-size (b/length plaintext))})
        [cryptor ciphertext] (tls13-crypto/encrypt cryptor plaintext header)]
    [cryptor (b/cat header ciphertext)]))

(defn decrypt-record
  "Decrypt record, return new cryptor, type and content."
  [cryptor ciphertext]
  (let [header (st/pack tls13-st/st-record-header
                        {:type tls13-st/content-type-application-data
                         :version tls13-st/version-tls12
                         :length (b/length ciphertext)})
        [cryptor plaintext] (tls13-crypto/decrypt cryptor ciphertext header)
        [type content] (tls13-st/unpack-inner-plaintext plaintext)]
    [cryptor type content]))

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
  (recv-ciphertext context :application-decryptor content))

(defn send-change-cipher-spec
  "Send change cipher spec."
  [context]
  (send-plaintext
   context
   tls13-st/content-type-change-cipher-spec
   (st/pack tls13-st/st-change-cipher-spec tls13-st/change-ciper-spec)))

(defn recv-change-cipher-spec
  "Recv change cipher spec."
  [context content]
  (let [change-cipher-spec (st/unpack tls13-st/st-change-cipher-spec content)]
    (if (= change-cipher-spec tls13-st/change-ciper-spec)
      context
      (throw (ex-info "invalid change cipher spec" {:reason ::invalid-change-cipher-spec :change-cipher-spec change-cipher-spec})))))

(defmulti recv-record
  "Recv record, return new context."
  (fn [context _type _content] (:stage context)))

;;; client

;;;; client hello

(def default-client-opts
  {:stage                :wait-server-hello
   :signature-algorithms [tls13-st/signature-scheme-ed25519
                          tls13-st/signature-scheme-ed448
                          tls13-st/signature-scheme-ecdsa-secp256r1-sha256
                          tls13-st/signature-scheme-ecdsa-secp384r1-sha384
                          tls13-st/signature-scheme-ecdsa-secp521r1-sha512
                          tls13-st/signature-scheme-rsa-pkcs1-sha256
                          tls13-st/signature-scheme-rsa-pkcs1-sha384
                          tls13-st/signature-scheme-rsa-pkcs1-sha512]
   :cipher-suites        [tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                          tls13-st/cipher-suite-tls-aes-256-gcm-sha384
                          tls13-st/cipher-suite-tls-chacha20-poly1305-sha256]
   :named-groups         [tls13-st/named-group-x25519]})

(defn init-client-random
  "Init client random."
  [context]
  (merge context {:client-random (b/rand 32)}))

(defn init-client-key-shares
  "Init client key shares."
  [context]
  (let [{:keys [named-groups]} context
        key-shares (->> named-groups (mapv tls13-crypto/gen-key-share))]
    (merge context {:key-shares key-shares})))

(defn pack-client-extension-supported-versions
  "Pack supported versions extension."
  [context]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-supported-versions
   (st/pack tls13-st/st-extension-supported-versions-client-hello [tls13-st/version-tls13])))

(defn pack-client-extension-signature-algorithms
  "Pack signature algorithms extension."
  [{:keys [signature-algorithms] :as context}]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-signature-algorithms
   (st/pack tls13-st/st-extension-signature-algorithms signature-algorithms)))

(defn pack-client-extension-supported-groups
  "Pack supported groups extension."
  [{:keys [named-groups] :as context}]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-supported-groups
   (st/pack tls13-st/st-extension-supported-groups named-groups)))

(defn pack-client-extension-key-share
  "Pack key share extension."
  [{:keys [key-shares] :as context}]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-key-share
   (st/pack tls13-st/st-extension-key-share-client-hello
            (->> key-shares
                 (map
                  (fn [{:keys [named-group] :as key-share}]
                    {:group named-group :key-exchange (tls13-crypto/key-share->pub-bytes key-share)}))))))

(defn pack-client-extension-server-name
  "Pack server name extension."
  [{:keys [server-names] :as context}]
  (cond-> context
    (seq server-names)
    (pack-extension
     :client-extensions
     tls13-st/extension-type-server-name
     (st/pack tls13-st/st-extension-server-name-client-hello
              (->> server-names
                   (map
                    (fn [server-name]
                      {:name-type 0 :name server-name})))))))

(defn pack-client-extension-application-layer-protocol-negotiation
  "Pack application layer protocol negotiation extension."
  [{:keys [application-protocols] :as context}]
  (cond-> context
    (seq application-protocols)
    (pack-extension
     :client-extensions
     tls13-st/extension-type-application-layer-protocol-negotiation
     (st/pack tls13-st/st-extension-application-layer-protocol-negotiation application-protocols))))

(defn send-client-hello
  "Send client hello."
  [context]
  (let [{:keys [client-random cipher-suites client-extensions]} context]
    (send-handshake-plaintext
     context
     tls13-st/handshake-type-client-hello
     (st/pack tls13-st/st-handshake-client-hello
              {:legacy-version tls13-st/version-tls12
               :random client-random
               :legacy-session-id (byte-array 0)
               :cipher-suites cipher-suites
               :legacy-compression-methods [tls13-st/compression-method-null]
               :extensions client-extensions}))))

(defn ->client-context
  "Construct initial client context."
  [opts]
  (-> (merge default-client-opts opts)
      init-client-random
      init-client-key-shares
      pack-client-extension-supported-versions
      pack-client-extension-signature-algorithms
      pack-client-extension-supported-groups
      pack-client-extension-key-share
      pack-client-extension-server-name
      pack-client-extension-application-layer-protocol-negotiation
      send-client-hello))

;;;; server hello

(defn unpack-server-extension-supported-versions
  "Unpack supported versions extension."
  [context]
  (if-let [[_ extension] (find-extension context :server-extensions tls13-st/extension-type-supported-versions)]
    (let [selected-version (st/unpack tls13-st/st-extension-supported-versions-server-hello extension)]
      (if (= selected-version tls13-st/version-tls13)
        context
        (throw (ex-info "invalid version" {:reason ::invalid-version :version selected-version}))))
    (throw (ex-info "no selected version" {:reason ::no-selected-version}))))

(defn unpack-server-extension-key-share
  "Unpack key share extension."
  [{:keys [key-shares] :as context}]
  (if-let [[_ extension] (find-extension context :server-extensions tls13-st/extension-type-key-share)]
    (let [{:keys [key-exchange] selected-named-group :group}
          (st/unpack tls13-st/st-extension-key-share-server-hello extension)]
      (if-let [key-share (->> key-shares (filter #(= selected-named-group (:named-group %))) first)]
        (let [shared-secret (tls13-crypto/key-agreement key-share key-exchange)]
          (merge context {:named-group selected-named-group :shared-secret shared-secret}))
        (throw (ex-info "invalid named group" {:reason ::invalid-named-group :named-group selected-named-group}))))
    (throw (ex-info "no selected key share" {:reason ::no-selected-key-share}))))

(defn init-client-early-secret
  "Init early secret."
  [{:keys [cipher-suite] :as context}]
  (merge context {:early-secret (tls13-crypto/early-secret cipher-suite)}))

(defn init-client-handshake-secret
  "Init handshake secret."
  [{:keys [cipher-suite early-secret shared-secret handshake-msgs] :as context}]
  (let [digest-size (tls13-crypto/digest-size cipher-suite)
        handshake-secret (tls13-crypto/handshake-secret cipher-suite early-secret shared-secret)
        client-handshake-secret (tls13-crypto/client-handshake-secret cipher-suite handshake-secret handshake-msgs)
        server-handshake-secret (tls13-crypto/server-handshake-secret cipher-suite handshake-secret handshake-msgs)
        client-handshake-verify-key (tls13-crypto/hkdf-expand-label cipher-suite client-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        server-handshake-verify-key (tls13-crypto/hkdf-expand-label cipher-suite server-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        handshake-encryptor (tls13-crypto/->cryptor cipher-suite client-handshake-secret)
        handshake-decryptor (tls13-crypto/->cryptor cipher-suite server-handshake-secret)]
    (merge
     context
     {:handshake-secret handshake-secret
      :client-handshake-secret client-handshake-secret
      :server-handshake-secret server-handshake-secret
      :client-handshake-verify-key client-handshake-verify-key
      :server-handshake-verify-key server-handshake-verify-key
      :handshake-encryptor handshake-encryptor
      :handshake-decryptor handshake-decryptor})))

(defmethod recv-record :wait-server-hello [context type content]
  (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
    (case msg-type
      tls13-st/handshake-type-server-hello
      (let [{:keys [cipher-suites]} context
            {:keys [random cipher-suite extensions]} (st/unpack tls13-st/st-handshake-server-hello msg-data)]
        (if (contains? (set cipher-suites) cipher-suite)
          (-> context
              (merge
               {:stage :wait-server-ccs-ee
                :cipher-suite cipher-suite
                :server-random random
                :server-extensions extensions})
              unpack-server-extension-supported-versions
              unpack-server-extension-key-share
              init-client-early-secret
              init-client-handshake-secret)
          (throw (ex-info "invalid cipher suite" {:reason ::invalid-cipher-suite :cipher-suite cipher-suite}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; server encrypted extensions

(defmethod recv-record :wait-server-ccs-ee [context type content]
  (case type
    tls13-st/content-type-application-data
    (-> context
        (merge {:stage :wait-server-ee})
        (recv-record type content))
    tls13-st/content-type-change-cipher-spec
    (-> context
        (recv-change-cipher-spec content)
        (merge {:stage :wait-server-ee}))
    (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))

(defn unpack-server-encrypted-extension-application-layer-protocol-negotiation
  [{:keys [application-protocols] :as context}]
  (if-let [[_ extension] (find-extension context :server-encrypted-extensions tls13-st/extension-type-application-layer-protocol-negotiation)]
    (let [selected-application-protocols (st/unpack tls13-st/st-extension-application-layer-protocol-negotiation extension)]
      (if (= 1 (count selected-application-protocols))
        (let [selected-application-protocol (first selected-application-protocols)]
          (if (contains? (set application-protocols) selected-application-protocol)
            (merge context {:application-protocol selected-application-protocol})
            (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :application-protocols selected-application-protocols}))))
        (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :application-protocols selected-application-protocols}))))
    context))

(defmethod recv-record :wait-server-ee [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-encrypted-extensions
      (let [extensions (st/unpack tls13-st/st-handshake-encrypted-extensions msg-data)]
        (-> context
            (merge {:stage :wait-server-cert-cr :server-encrypted-extensions extensions})
            unpack-server-encrypted-extension-application-layer-protocol-negotiation))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; server certificate

(defn recv-server-certificate
  "Recv server certificate plaintext."
  ([context msg-type msg-data]
   (case msg-type
     tls13-st/handshake-type-certificate
     (recv-server-certificate context msg-data)
     (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type}))))
  ([context msg-data]
   (let [{:keys [certificate-request-context certificate-list]}
         (st/unpack tls13-st/st-handshake-certificate msg-data)
         certificate-list (->> certificate-list
                               (mapv
                                (fn [{:keys [cert-data extensions]}]
                                  {:certificate (tls13-crypto/bytes->cert cert-data)
                                   :extensions extensions})))]
     (merge
      context
      {:stage :wait-server-cv
       :server-certificate-request-context certificate-request-context
       :server-certificate-list certificate-list}))))

(defmethod recv-record :wait-server-cert-cr [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (if (= msg-type tls13-st/handshake-type-certificate-request)
      (let [{:keys [certificate-request-context extensions]}
            (st/unpack tls13-st/st-handshake-certificate-request msg-data)]
        (merge
         context
         {:stage :wait-server-cert
          :client-auth? true
          :client-certificate-request-context certificate-request-context
          :server-certificate-reuqest-extensions extensions}))
      (recv-server-certificate context msg-type msg-data))))

(defmethod recv-record :wait-server-cert [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (recv-server-certificate context msg-type msg-data)))

(defmethod recv-record :wait-server-cv [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-certificate-verify
      (let [{:keys [cipher-suite signature-algorithms server-certificate-list handshake-msgs]} context
            certificate (:certificate (first server-certificate-list))
            {:keys [algorithm signature]} (st/unpack tls13-st/st-handshake-certificate-verify msg-data)]
        (if (and (contains? algorithm signature-algorithms)
                 (= algorithm (tls13-crypto/cert->signature-scheme certificate)))
          (let [signature-data (tls13-st/pack-signature-data
                                tls13-st/server-signature-context-string
                                (apply tls13-crypto/digest cipher-suite (butlast handshake-msgs)))]
            (if (tls13-crypto/verify certificate signature-data signature)
              (merge context {:stage :wait-server-finished})
              (throw (ex-info "invalid signature" {:reason ::invalid-signature}))))
          (throw (ex-info "invalid signature algorithm" {:reason ::invalid-signature-algorithm :signature-algorithm algorithm}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; server finished

(defn verify-server-finished
  "Verify finished."
  [context msg-data]
  (let [{:keys [cipher-suite server-handshake-verify-key handshake-msgs]} context
        verify (tls13-crypto/hmac cipher-suite
                                  server-handshake-verify-key
                                  (apply tls13-crypto/digest cipher-suite (butlast handshake-msgs)))]
    (if (zero? (b/compare msg-data verify))
      context
      (throw (ex-info "invalid finished" {:reason ::invalid-finished})))))

(defn send-client-certificate
  "Send certificate."
  [context]
  (let [{:keys [client-certificate-list client-certificate-request-context]} context]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate
     (st/pack tls13-st/st-handshake-certificate
              {:certificate-request-context client-certificate-request-context
               :certificate-list (->> client-certificate-list
                                      (map
                                       (fn [{:keys [certificate extensions]}]
                                         {:cert-data (tls13-crypto/cert->bytes certificate)
                                          :extensions extensions})))}))))

(defn send-client-certificate-verify
  "Send certificate verify."
  [context]
  (let [{:keys [cipher-suite client-certificate-list client-private-key handshake-msgs]} context
        certificate (:certificate (first client-certificate-list))
        signature-data (tls13-st/pack-signature-data
                        tls13-st/client-signature-context-string
                        (apply tls13-crypto/digest cipher-suite handshake-msgs))
        signature (tls13-crypto/sign certificate client-private-key signature-data)]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate-verify
     (st/pack tls13-st/st-handshake-certificate-verify
              {:algorithm (tls13-crypto/cert->signature-scheme certificate)
               :signature signature}))))

(defn send-client-auth
  "Send client auth."
  [context]
  (if-not (:client-auth? context)
    context
    (if (and (some? (:client-certificate-list context))
             (some? (:client-private-key context)))
      (-> context
          send-client-certificate
          send-client-certificate-verify)
      (throw (ex-info "require client auth" {:reason ::require-client-auth})))))

(defn send-client-finished
  "Send finished."
  [{:keys [cipher-suite client-handshake-verify-key handshake-msgs] :as context}]
  (let [verify (tls13-crypto/hmac cipher-suite
                                  client-handshake-verify-key
                                  (apply tls13-crypto/digest cipher-suite handshake-msgs))]
    (send-handshake-ciphertext context tls13-st/handshake-type-finished verify)))

(defn init-client-master-secret
  "Init master secret."
  [{:keys [cipher-suite handshake-secret handshake-msgs] :as context}]
  (let [master-secret (tls13-crypto/master-secret cipher-suite handshake-secret)
        client-application-secret (tls13-crypto/client-application-secret cipher-suite master-secret handshake-msgs)
        server-application-secret (tls13-crypto/server-application-secret cipher-suite master-secret handshake-msgs)
        application-encryptor (tls13-crypto/->cryptor cipher-suite client-application-secret)
        application-decryptor (tls13-crypto/->cryptor cipher-suite server-application-secret)]
    (merge
     context
     {:master-secret master-secret
      :client-application-secret client-application-secret
      :server-application-secret server-application-secret
      :application-decryptor application-decryptor
      :application-encryptor application-encryptor})))

(defmethod recv-record :wait-server-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-server-finished msg-data)
          send-change-cipher-spec
          send-client-auth
          send-client-finished
          init-client-master-secret)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;; server

;;;; server hello

(def default-server-opts
  {:stage                :wait-client-hello
   :cipher-suites        [tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                          tls13-st/cipher-suite-tls-aes-256-gcm-sha384
                          tls13-st/cipher-suite-tls-chacha20-poly1305-sha256]
   :named-groups         [tls13-st/named-group-x25519
                          tls13-st/named-group-x448
                          tls13-st/named-group-secp256r1
                          tls13-st/named-group-secp384r1
                          tls13-st/named-group-secp521r1]})

(defn ->server-context
  "Construct server context."
  [opts]
  (merge default-server-opts opts))

(defn init-server-random
  "Init server random."
  [context]
  (merge context {:server-random (b/rand 32)}))

(defn unpack-client-extension-supported-versions
  "Unpack supported versions extension."
  [context]
  (if-let [[_ extension] (find-extension context :client-extensions tls13-st/extension-type-supported-versions)]
    (let [supported-versions (st/unpack tls13-st/st-extension-supported-versions-server-hello extension)]
      (if (contains? (set supported-versions) tls13-st/version-tls13)
        context
        (throw (ex-info "invalid versions" {:reason ::invalid-versions :versions supported-versions}))))
    (throw (ex-info "no supported versions" {:reason ::no-supported-versions}))))

(defn unpack-client-extension-key-share
  "Unpack key share extension."
  [context]
  (if-let [[_ extension] (find-extension context :client-extensions tls13-st/extension-type-supported-groups)]
    (let [server-named-groups (set (:named-groups context))
          supported-key-shares (st/unpack tls13-st/st-extension-key-share-client-hello extension)]
      (if-let [{:keys [key-exchange] selected-named-group :group}
               (->> supported-key-shares (filter #(contains? server-named-groups (:group %))) first)]
        (let [key-share (tls13-crypto/gen-key-share selected-named-group)
              shared-secret (tls13-crypto/key-agreement key-share key-exchange)]
          (merge context {:key-share key-share :named-group selected-named-group :shared-secret shared-secret}))
        (throw (ex-info "invalid key shares" {:reason ::invalid-named-groups :named-groups (->> supported-key-shares (mapv :group))}))))
    (throw (ex-info "no supported key shares" {:reason ::no-supported-key-shares}))))

(defn unpack-client-extension-server-name
  "Unpack server name extension."
  [context]
  (if-let [[_ extension] (find-extension context :client-extensions tls13-st/extension-type-supported-groups)]
    (let [server-names (->> (st/unpack tls13-st/st-extension-server-name-client-hello extension)
                            (map
                             (fn [{:keys [name-type name]}]
                               (if (= name-type 0)
                                 name
                                 (throw (ex-info "invalid server name type" {:reason ::invalid-server-name-type :name-type name-type}))))))]
      (merge context {:server-names server-names}))
    context))

(defn unpack-client-extension-application-layer-protocol-negotiation
  "Unpack application layer protocol negotiation extension."
  [context]
  (if (seq (:application-protocols context))
    (if-let [[_ extension] (find-extension context :client-extensions tls13-st/extension-type-application-layer-protocol-negotiation)]
      (let [server-application-protocols (set (:application-protocols context))
            supported-application-protocols (st/unpack tls13-st/st-extension-application-layer-protocol-negotiation)]
        (if-let [selected-application-protocol (->> supported-application-protocols (some server-application-protocols))]
          (merge context {:application-protocol selected-application-protocol})
          (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :application-protocols supported-application-protocols}))))
      context)
    context))

(defn pack-server-extension-supported-versions
  "Pack supported versions extension."
  [context]
  (pack-extension
   context :server-extensions
   tls13-st/extension-type-supported-versions
   (st/pack tls13-st/st-extension-supported-versions-server-hello tls13-st/version-tls13)))

(defn pack-server-extension-key-share
  "Pack key share extension."
  [{:keys [key-share named-group] :as context}]
  (pack-extension
   context :server-extensions
   tls13-st/extension-type-key-share
   (st/pack tls13-st/st-extension-key-share-server-hello
            {:group named-group :key-exchange (tls13-crypto/key-share->pub-bytes key-share)})))

(defn pack-server-encrypted-extension-server-name
  "Pack server name extension."
  [{:keys [server-names] :as context}]
  (cond-> context
    (some? server-names)
    (pack-extension
     :server-encrypted-extensions
     tls13-st/extension-type-server-name (byte-array 0))))

(defn pack-server-encrypted-extension-application-layer-protocol-negotiation
  "Pack application layer protocol negotiation extension."
  [{:keys [application-protocol] :as context}]
  (cond-> context
    (some? application-protocol)
    (pack-extension
     :server-encrypted-extensions
     tls13-st/extension-type-application-layer-protocol-negotiation [application-protocol])))

(defn send-server-hello
  "Send server hello."
  [context]
  (let [{:keys [server-random cipher-suite server-extensions]} context]
    (send-handshake-plaintext
     context
     tls13-st/handshake-type-server-hello
     (st/pack tls13-st/st-handshake-server-hello
              {:legacy-version tls13-st/version-tls12
               :random server-random
               :legacy-session-id-echo (byte-array 0)
               :cipher-suite cipher-suite
               :legacy-compression-method tls13-st/compression-method-null
               :extensions server-extensions}))))

(defn init-server-early-secret
  "Init early secret."
  [{:keys [cipher-suite] :as context}]
  (merge context {:early-secret (tls13-crypto/early-secret cipher-suite)}))

(defn init-server-handshake-secret
  "Init handshake secret."
  [{:keys [cipher-suite early-secret shared-secret handshake-msgs] :as context}]
  (let [digest-size (tls13-crypto/digest-size cipher-suite)
        handshake-secret (tls13-crypto/handshake-secret cipher-suite early-secret shared-secret)
        client-handshake-secret (tls13-crypto/client-handshake-secret cipher-suite handshake-secret handshake-msgs)
        server-handshake-secret (tls13-crypto/server-handshake-secret cipher-suite handshake-secret handshake-msgs)
        client-handshake-verify-key (tls13-crypto/hkdf-expand-label cipher-suite client-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        server-handshake-verify-key (tls13-crypto/hkdf-expand-label cipher-suite server-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        handshake-encryptor (tls13-crypto/->cryptor cipher-suite server-handshake-secret)
        handshake-decryptor (tls13-crypto/->cryptor cipher-suite client-handshake-secret)]
    (merge
     context
     {:handshake-secret handshake-secret
      :client-handshake-secret client-handshake-secret
      :server-handshake-secret server-handshake-secret
      :client-handshake-verify-key client-handshake-verify-key
      :server-handshake-verify-key server-handshake-verify-key
      :handshake-encryptor handshake-encryptor
      :handshake-decryptor handshake-decryptor})))

(defn send-server-encrypted-extensions
  "Send encrypted extensions."
  [context]
  (let [{:keys [server-encrypted-extensions]} context]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-encrypted-extensions
     (st/pack tls13-st/st-handshake-encrypted-extensions server-encrypted-extensions))))

(defn send-server-certificate
  "Send certificate."
  [context]
  (let [{:keys [server-certificate-list]} context]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate
     (st/pack tls13-st/st-handshake-certificate
              {:certificate-request-context (byte-array 0)
               :certificate-list (->> server-certificate-list
                                      (map
                                       (fn [{:keys [certificate extensions]}]
                                         {:cert-data (tls13-crypto/cert->bytes certificate)
                                          :extensions extensions})))}))))

(defn send-server-certificate-verify
  "Send certificate verify."
  [context]
  (let [{:keys [cipher-suite server-certificate-list server-private-key handshake-msgs]} context
        certificate (:certificate (first server-certificate-list))
        signature-data (tls13-st/pack-signature-data
                        tls13-st/server-signature-context-string
                        (apply tls13-crypto/digest cipher-suite handshake-msgs))
        signature (tls13-crypto/sign certificate server-private-key signature-data)]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate-verify
     (st/pack tls13-st/st-handshake-certificate-verify
              {:algorithm (tls13-crypto/cert->signature-scheme certificate)
               :signature signature}))))

(defn send-server-auth
  "Send server auth."
  [context]
  (-> context
      send-server-certificate
      send-server-certificate-verify))

(defn send-server-finished
  "Send finished."
  [{:keys [cipher-suite server-handshake-verify-key handshake-msgs] :as context}]
  (let [verify (tls13-crypto/hmac cipher-suite
                                  server-handshake-verify-key
                                  (apply tls13-crypto/digest cipher-suite handshake-msgs))]
    (send-handshake-ciphertext context tls13-st/handshake-type-finished verify)))

(defmethod recv-record :wait-client-hello [context type content]
  (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
    (case msg-type
      tls13-st/handshake-type-client-hello
      (let [server-cipher-suites (set (:cipher-suites context))
            {:keys [random cipher-suites extensions]} (st/unpack tls13-st/st-handshake-client-hello msg-data)]
        (if-let [cipher-suite (->> cipher-suites (some server-cipher-suites))]
          (-> context
              (merge
               {:stage :wait-client-finished
                :cipher-suite cipher-suite
                :client-random random
                :client-extensions extensions})
              init-server-random
              unpack-client-extension-supported-versions
              unpack-client-extension-key-share
              unpack-client-extension-server-name
              unpack-client-extension-application-layer-protocol-negotiation
              pack-server-extension-supported-versions
              pack-server-extension-key-share
              pack-server-encrypted-extension-server-name
              pack-server-encrypted-extension-application-layer-protocol-negotiation
              send-server-hello
              send-change-cipher-spec
              init-server-early-secret
              init-server-handshake-secret
              send-server-encrypted-extensions
              send-server-auth
              send-server-finished)
          (throw (ex-info "invalid cipher suites" {:reason ::invalid-cipher-suites :cipher-suites cipher-suites}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; finished

(defn verify-client-finished
  "Verify finished."
  [context msg-data]
  (let [{:keys [cipher-suite client-handshake-verify-key handshake-msgs]} context
        verify (tls13-crypto/hmac cipher-suite
                                  client-handshake-verify-key
                                  (apply tls13-crypto/digest cipher-suite (butlast handshake-msgs)))]
    (if (zero? (b/compare msg-data verify))
      context
      (throw (ex-info "invalid finished" {:reason ::invalid-finished})))))

(defn init-server-master-secret
  "Init master secret."
  [{:keys [cipher-suite handshake-secret handshake-msgs] :as context}]
  (let [master-secret (tls13-crypto/master-secret cipher-suite handshake-secret)
        client-application-secret (tls13-crypto/client-application-secret cipher-suite master-secret handshake-msgs)
        server-application-secret (tls13-crypto/server-application-secret cipher-suite master-secret handshake-msgs)
        application-encryptor (tls13-crypto/->cryptor cipher-suite server-application-secret)
        application-decryptor (tls13-crypto/->cryptor cipher-suite client-application-secret)]
    (merge
     context
     {:master-secret master-secret
      :client-application-secret client-application-secret
      :server-application-secret server-application-secret
      :application-decryptor application-decryptor
      :application-encryptor application-encryptor})))

(defmethod recv-record :wait-client-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (case msg-type
      tls13-st/handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-client-finished msg-data)
          init-server-master-secret)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))
