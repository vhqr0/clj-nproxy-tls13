(ns clj-nproxy.plugin.tls13.context
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto :as tls13-crypto]))

;;; cryptor

(defn mask-bytes-inplace
  "Mask bytes one by one inplace."
  [^bytes b1 ^bytes b2]
  (let [b1 (bytes b1)
        b2 (bytes b2)]
    (dotimes [idx (alength b1)]
      (aset b1 idx (unchecked-byte (bit-xor (aget b1 idx) (aget b2 idx)))))))

(def st-hkdf-label
  (st/keys
   :length st/st-ushort-be
   :label (st/->st-var-bytes st/st-ubyte)
   :context (st/->st-var-bytes st/st-ubyte)))

(defn hkdf-expand-label
  "Expand label."
  ^bytes [cryptor secret label context length]
  (let [{:keys [hkdf-expand-fn]} cryptor
        info (st/pack st-hkdf-label length label context)]
    (hkdf-expand-fn secret info length)))

(defn hkdf-derive-secret
  "Derive secret."
  ^bytes [cryptor secret label messages]
  (let [{:keys [digest-fn digest-size]} cryptor
        info (apply digest-fn messages)]
    (hkdf-expand-label cryptor secret label info digest-size)))

(defn reset-key
  "Reset key in cryptor with new secret.
  Recalculate key and iv, derived from secret.
  Reset sequence to zero."
  [cryptor secret]
  (let [{:keys [aead-key-size aead-iv-size]} cryptor
        key (hkdf-expand-label cryptor secret (:key tls13-st/label-map) (byte-array 0) aead-key-size)
        iv (hkdf-expand-label cryptor secret (:iv tls13-st/label-map) (byte-array 0) aead-iv-size)]
    (merge cryptor {:secret secret :key key :iv iv :sequence 0})))

(defn update-key
  "Update key in cryptor.
  Derive a new secret based on current secret.
  Reset key with new secret."
  [cryptor]
  (let [{:keys [secret digest-size]} cryptor
        secret (hkdf-expand-label cryptor secret (:key-update tls13-st/label-map) (byte-array 0) digest-size)]
    (reset-key cryptor secret)))

(defn inc-sequence
  "Inc sequence."
  [cryptor]
  (update cryptor :sequence inc))

(defn get-sequence-iv
  "Get iv of current sequence."
  [cryptor]
  (let [{:keys [sequence iv]} cryptor]
    (doto (b/right-align (st/pack-long-be sequence) (b/length iv))
      (mask-bytes-inplace iv))))

(defn encrypt
  "Encrypt."
  [cryptor plaintext aad]
  (let [{:keys [aead-encrypt-fn key]} cryptor
        iv (get-sequence-iv cryptor)]
    (aead-encrypt-fn key iv plaintext aad)))

(defn decrypt
  "Decrypt."
  [cryptor ciphertext aad]
  (let [{:keys [aead-decrypt-fn key]} cryptor
        iv (get-sequence-iv cryptor)]
    (aead-decrypt-fn key iv ciphertext aad)))

(defn encrypt-record
  "Encrypt record."
  [cryptor type content]
  (let [{:keys [aead-tag-size]} cryptor
        inner-plaintext (tls13-st/pack-inner-plaintext type content)
        header (st/pack tls13-st/st-record-header
                        23 ; application-data
                        0x0303 ; tls12
                        (+ aead-tag-size (b/length inner-plaintext)))
        encrypted-record (encrypt cryptor inner-plaintext header)]
    (b/cat header encrypted-record)))

(defn decrypt-record
  "Decrypt record."
  [cryptor encrypted-record]
  (let [header (st/pack tls13-st/st-record-header
                        23 ; application-data
                        0x0303 ; tls12
                        (b/length encrypted-record))
        inner-plaintext (decrypt cryptor encrypted-record header)
        {:keys [type content]} (tls13-st/unpack-inner-plaintext inner-plaintext)]
    [type content]))

(defn named-group->key-share
  "Expand group to key share."
  [named-group]
  (if-let [{:keys [gen-fn] :as group} (get tls13-crypto/named-group-map named-group)]
    (let [[pri pub] (gen-fn)]
      (merge group {:group named-group :pri pri :pub pub}))
    (throw (st/data-error))))

(defn key-agreement
  "Key agreement."
  [key-share selected-key-share]
  (let [{:keys [pri bytes->pub-fn key-agreement-fn]} key-share
        {:keys [key-exchange]} selected-key-share]
    (key-agreement-fn pri (bytes->pub-fn key-exchange))))

;;; context

;; stage: wait-sh wait-ccs-ee wait-ee wait-cert-cr wait-cert wait-cv wait-finished connected

(declare send-client-hello)

(defn init-context
  "Construct init context."
  [{:keys [versions
           signature-algorithms
           cipher-suites
           named-groups
           server-names
           application-protocols]
    :or {versions [0x0304]
         signature-algorithms [0x0807 0x0808 0x0403 0x0503 0x0603]
         cipher-suites [0x1301 0x1302 0x1303]
         named-groups [0x001d 0x001e]}}]
  (let [client-random (b/rand 32)
        key-shares (->> named-groups (mapv named-group->key-share))
        context {:stage :wait-sh
                 :versions versions
                 :signature-algorithms signature-algorithms
                 :cipher-suites cipher-suites
                 :named-groups named-groups
                 :server-names server-names
                 :application-protocols application-protocols
                 :client-random client-random
                 :key-shares key-shares}]
    (send-client-hello context)))

;; client hello, change cipher spec
(defn send-plaintext
  "Send plaintext."
  [context type content]
  (let [record (st/pack tls13-st/st-record {:type type :version 0x0303 :content content})]
    (update :send-bytes (fnil conj []) record)))

(defn send-ciphertext
  "Send ciphertext."
  [encryptor-key context type content]
  (let [encryptor (get context encryptor-key)
        record (encrypt-record encryptor type content)]
    (-> context
        (update encryptor-key inc-sequence)
        (update :send-bytes (fnil conj []) record))))

;; client finished
(def send-handshake-ciphertext (partial send-ciphertext :handshake-encryptor))

;; early data, end of early data
(def send-early-ciphertext (partial send-ciphertext :early-encryptor))

;; post handshake early data
(def send-application-ciphertext (partial send-ciphertext :application-encryptor))

(defn pack-supported-versions
  [{:keys [versions]}]
  (st/pack tls13-st/st-supported-version-client-hello versions))

(defn pack-signature-algorithms
  [{:keys [signature-algorithms]}]
  (st/pack tls13-st/st-signature-scheme-list signature-algorithms))

(defn pack-supported-groups
  [{:keys [named-groups]}]
  (st/pack tls13-st/st-named-group-list named-groups))

(defn pack-key-share
  [{:keys [key-shares]}]
  (st/pack tls13-st/st-key-share-client-hello
           (->> key-shares
                (map
                 (fn [{:keys [group pub pub->bytes-fn]}]
                   {:group group :key-exchange (pub->bytes-fn pub)})))))

(defn pack-server-name
  [{:keys [server-names]}]
  (when (seq server-names)
    (st/pack tls13-st/st-server-name-host
             (->> server-names
                  (map
                   (fn [server-name]
                     {:name-type 0 :name server-name}))))))

(defn pack-application-layer-protocol-negotiation
  [{:keys [application-protocols]}]
  (when (seq application-protocols)
    (st/pack tls13-st/st-protocol-name-list application-protocols)))

(defn send-client-hello
  "Second client hello."
  [context]
  (let [{:keys [client-random cipher-suites]} context
        extensions [[43 (pack-supported-versions context)]
                    [13 (pack-signature-algorithms context)]
                    [10 (pack-supported-groups context)]
                    [51 (pack-key-share context)]
                    [0 (pack-server-name context)]
                    [16 (pack-application-layer-protocol-negotiation context)]]
        extensions (->> extensions (remove (comp nil? second)))
        client-hello (st/pack tls13-st/st-client-hello
                              {:legacy-version 0x0303 ; tls12
                               :random client-random
                               :legacy-session-id (byte-array 0)
                               :cipher-suites cipher-suites
                               :legacy-compression-methods [0]
                               :extensions extensions})
        handshake (st/pack tls13-st/st-handshake
                           {:msg-type 1 ; client-hello
                            :msg-data client-hello})]
    (-> context
        (update :handshake-msgs (fnil conj []) handshake)
        (send-plaintext 22 handshake))))

(defn recv-ciphertext
  "Recv ciphertext, return new context and decrypted type, content."
  [decryptor-key context content]
  (let [decryptor (get context decryptor-key)
        [type content] (decrypt-record decryptor content)
        context (update context decryptor-key inc-sequence)]
    [context type content]))

(def recv-handshake-ciphertext (partial recv-ciphertext :handshake-decryptor))
(def recv-application-ciphertext (partial recv-ciphertext :application-decryptor))

(defmulti recv-record
  "Recv record, return new context."
  (fn [context _type _content] (:stage context)))

(defmethod recv-record :wait-sh [context type content]
  (if (= type 22)
    (let [context (update context :handshake-msgs (fnil conj []) content)
          {:keys [msg-type msg-data]} (st/unpack tls13-st/st-handshake content)]
      (if (= msg-type 1)
        (let [{:keys [cipher-suites named-groups application-protocols key-shares handshake-msgs]} context
              {:keys [extensions] server-random :random selected-cipher-suite :cipher-suite} (st/unpack tls13-st/st-server-hello msg-data)
              extension-map (into {} extensions)
              selected-version (some->> (get extension-map 43) (st/unpack tls13-st/st-supported-version-server-hello))
              {selected-named-group :group :as selected-key-share} (some->> (get extension-map 51) (st/unpack tls13-st/st-key-share-server-hello))
              selected-application-protocols (some->> (get extension-map 16) (st/unpack tls13-st/st-protocol-name-list))]
          (if (and (= selected-version 0x0304)
                   (contains? (set cipher-suites) selected-cipher-suite)
                   (contains? (set named-groups) selected-named-group)
                   (or (nil? selected-application-protocols)
                       (and (= 1 (count selected-application-protocols))
                            (contains? (set application-protocols) (first selected-application-protocols)))))
            (let [{:keys [hkdf-extract-fn digest-size] :as cipher-suite} (get tls13-crypto/cipher-suite-map selected-cipher-suite)
                  key-share (->> key-shares (filter #(= selected-named-group (:group %))) first)
                  shared-secret (key-agreement key-share selected-key-share)
                  ;; TODO support psk
                  early-secret (hkdf-extract-fn (byte-array digest-size) (byte-array digest-size))
                  handshake-secret (hkdf-extract-fn shared-secret (hkdf-derive-secret cipher-suite early-secret (:derived tls13-st/label-map) nil))
                  client-handshake-secret (hkdf-derive-secret cipher-suite handshake-secret (:client-handshake tls13-st/label-map) handshake-msgs)
                  server-handshake-secret (hkdf-derive-secret cipher-suite handshake-secret (:server-handshake tls13-st/label-map) handshake-msgs)
                  handshake-encryptor (reset-key cipher-suite client-handshake-secret)
                  handshake-decryptor (reset-key cipher-suite server-handshake-secret)]
              (merge
               context
               {:stage :wait-ccs-ee
                :server-random server-random
                :selected-cipher-suite selected-cipher-suite
                :selected-key-share selected-key-share
                :cipher-suite cipher-suite
                :shared-secret shared-secret
                :handshake-secret handshake-secret
                :handshake-encryptor handshake-encryptor
                :handshake-decryptor handshake-decryptor}
               (when (some? selected-application-protocols)
                 {:selected-application-protocol (first selected-application-protocols)})))
            (throw (st/data-error))))
        (throw (st/data-error))))
    (throw (st/data-error))))

(defmethod recv-record :wait-ccs-ee [context type content]
  (case type
    ;; change-cipher-spec
    20 (let [change-cipher-spec (st/unpack tls13-st/st-change-cipher-spec)]
         (if (= change-cipher-spec 1)
           (assoc context :stage :wait-ee)
           (throw (st/data-error))))
    ;; application-data
    23 (-> context
           (assoc :stage :wait-ee)
           (recv-record type content))))
