(ns clj-nproxy.plugin.tls13.context
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto :as tls13-crypto]))

;;; cryptor

(def st-hkdf-label
  (st/keys
   :length st/st-ushort-be
   :label (st/->st-var-bytes st/st-ubyte)
   :context (st/->st-var-bytes st/st-ubyte)))

(defn hkdf-expand-label
  ^bytes [cryptor secret label context length]
  (let [{:keys [hkdf-expand-fn]} cryptor
        info (st/pack st-hkdf-label length label context)]
    (hkdf-expand-fn secret info length)))

(defn hkdf-derive-secret
  ^bytes [cryptor secret label messages]
  (let [{:keys [digest-fn digest-size]} cryptor
        info (apply digest-fn messages)]
    (hkdf-expand-label cryptor secret label info digest-size)))

(defn reset-key
  [cryptor secret]
  (let [{:keys [aead-key-size aead-iv-size]} cryptor
        key (hkdf-expand-label cryptor secret (:key tls13-st/label-map) (byte-array []) aead-key-size)
        iv (hkdf-expand-label cryptor secret (:iv tls13-st/label-map) (byte-array []) aead-iv-size)]
    (merge cryptor {:secret secret :key key :iv iv :sequence 0})))

(defn update-key
  [cryptor]
  (let [{:keys [secret digest-size]} cryptor
        secret (hkdf-expand-label cryptor secret (:key-update tls13-st/label-map) (byte-array []) digest-size)]
    (reset-key cryptor secret)))

(defn inc-sequence
  [cryptor]
  (update cryptor :sequence inc))

(defn get-sequence-iv
  [cryptor]
  (let [{:keys [sequence iv]} cryptor]
    (doto (b/right-align (st/pack-long-be sequence) (b/length iv))
      (b/mask-bytes-inplace iv))))

(defn encrypt
  [cryptor plaintext aad]
  (let [{:keys [aead-encrypt-fn key]} cryptor
        iv (get-sequence-iv cryptor)]
    (aead-encrypt-fn key iv plaintext aad)))

(defn decrypt
  [cryptor ciphertext aad]
  (let [{:keys [aead-decrypt-fn key]} cryptor
        iv (get-sequence-iv cryptor)]
    (aead-decrypt-fn key iv ciphertext aad)))

(defn encrypt-record
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
  [cryptor encrypted-record]
  (let [header (st/pack tls13-st/st-record-header
                        23 ; application-data
                        0x0303 ; tls12
                        (b/length encrypted-record))
        inner-plaintext (decrypt cryptor encrypted-record header)
        {:keys [type content]} (tls13-st/unpack-inner-plaintext inner-plaintext)]
    [type content]))

;;; context

(defn init-context
  "Construct init context."
  [{:keys [server-names
           application-protocols
           signature-algorithms
           cipher-suites
           named-groups]
    :or {signature-algorithms (vals tls13-st/signature-scheme-map)
         cipher-suites [0x1301 0x1302 0x1303]
         named-groups [0x001d 0x001e]}}]
  {:stage :start
   :server-names server-names
   :application-protocols application-protocols
   :signature-algorithms signature-algorithms
   :cipher-suites cipher-suites
   :named-groups named-groups
   :client-random (b/rand 32)
   :client-shares (->> named-groups
                       (mapv
                        (fn [group]
                          (let [{:keys [gen-fn]} (get tls13-crypto/named-group-map group)
                                [pri pub] (gen-fn)]
                            {:group group :pri pri :pub pub}))))})
