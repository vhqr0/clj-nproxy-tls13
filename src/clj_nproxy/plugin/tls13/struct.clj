(ns clj-nproxy.plugin.tls13.struct
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]))

;; RFC 8446 TLS 1.3
;; RFC 6066 TLS Extensions
;; RFC 7301 TLS ALPN Extensions

(def st-uint24
  (-> (st/->st-bytes 3)
      (st/wrap
       #(st/unpack st/st-uint-be (b/cat (byte-array [0]) %))
       #(b/copy-of-range (st/pack st/st-uint-be %) 1 4))))

^:rct/test
(comment
  (seq (st/pack st-uint24 1)) ; => [0 0 1]
  (st/unpack st-uint24 (byte-array [0 0 1])) ; => 1
  )

;;; consts

(def hello-retry-request-random
  (b/hex->bytes "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"))

(def server-context-string
  "TLS 1.3, server CertificateVerify")
(def client-context-string
  "TLS 1.3, client CertificateVerify")

(def server-context-prefix
  (b/cat (byte-array (repeat 64 20))
         (b/str->bytes server-context-string)
         (byte-array [0])))

(def client-context-prefix
  (b/cat (byte-array (repeat 64 20))
         (b/str->bytes client-context-string)
         (byte-array [0])))

(def label-map
  {:derived               "tls13 derived"
   :external-binder       "tls13 ext binder"
   :resumption-binder     "tls13 res binder"
   :resumption-master     "tls13 res master"
   :resumption            "tls13 resumption"
   :exporter-master       "tls13 exp master"
   :early-exporter-master "tls13 e exp master"
   :client-early          "tls13 c e traffic"
   :client-handshake      "tls13 c hs traffic"
   :server-handshake      "tls13 s hs traffic"
   :client-application    "tls13 c ap traffic"
   :server-application    "tls13 s ap traffic"
   :key-update            "tls13 traffic upd"
   :key                   "tls13 key"
   :iv                    "tls13 iv"
   :finished              "tls13 finished"})

;;; compatible

(def protocol-version-map
  {:ssl30 0x0300
   :tls10 0x0301
   :tls11 0x0302
   :tls12 0x0303
   :tls13 0x0304})

(def st-protocol-version st/st-ushort-be)
(def st-protocol-version-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-protocol-version)))

(def change-cipher-spec-map
  {:change-ciper-spec 1})

(def st-change-cipher-spec st/st-ubyte)

(def compression-method-map
  {:null 0})

(def st-compression-method st/st-ubyte)
(def st-compression-method-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-compression-method)))

;;; b.1 record layer

(def content-type-map
  {:invalid            0
   :change-cipher-spec 20
   :alert              21
   :handshake          22
   :application-data   23
   :heartbeat          24})

(def st-content-type st/st-ubyte)

(def st-plaintext
  (st/keys :type st-content-type
           :legacy-record-version st-protocol-version
           :fragment (st/->st-var-bytes st/st-ushort-be)))

(def st-ciphertext
  (st/keys :opaque-type st-content-type ; application-data
           :legacy-record-version st-protocol-version ; tls12
           :encrypted-record (st/->st-var-bytes st/st-ushort-be)))

(def st-record-header
  (st/keys :type st-content-type
           :version st-protocol-version
           :length st/st-ushort-be))

(def st-record
  (st/keys :type st-content-type
           :version st-protocol-version
           :content (st/->st-var-bytes st/st-ushort-be)))

(defn unpack-inner-plaintext
  "Unpack inner plaintext."
  [^bytes b]
  (let [b (bytes b)
        l (alength b)
        i (loop [i (dec l)]
            (if (zero? i)
              (throw st/data-error)
              (if-not (zero? (aget b i))
                i
                (recur (dec i)))))
        type (aget b i)
        content (b/copy-of b i)]
    [type content (dec (- l i))]))

^:rct/test
(comment
  (-> (unpack-inner-plaintext (byte-array [1 2 3 4 0 0])) (update 1 seq)) ; => [4 [1 2 3] 2]
  )

(defn pack-inner-plaintext
  "Pack inner plaintext."
  ([type content]
   (b/cat content (byte-array [type])))
  ([type content plen]
   (b/cat content (byte-array [type]) (byte-array plen))))

^:rct/test
(comment
  (seq (pack-inner-plaintext 1 (byte-array [2 3 4]))) ; => [2 3 4 1]
  (seq (pack-inner-plaintext 1 (byte-array [2 3 4]) 2)) ; => [2 3 4 1 0 0]
  )

;;; b.2 alert messages

(def alert-level-map
  {:warning 1 :fatal 2})

(def st-alert-level st/st-ubyte)

(def alert-description-map
  {:close-notify                        0
   :unexpected-message                  10
   :bad-record-mac                      20
   :decryption-failed-RESERVED          21
   :record-overflow                     22
   :decompression-failure-RESERVED      30
   :handshake-failure                   40
   :no-certificate-RESERVED             41
   :bad-certificate                     42
   :unsupported-certificate             43
   :certificate-revoked                 44
   :certificate-expired                 45
   :certificate-unknown                 46
   :illegal-parameter                   47
   :unknown-ca                          48
   :access-denied                       49
   :decode-error                        50
   :decrypt-error                       51
   :export-restriction-RESERVED         60
   :protocol-version                    70
   :insufficient-security               71
   :internal-error                      80
   :inappropriate-fallback              86
   :user-canceled                       90
   :no-renegotiation-RESERVED           100
   :missing-extension                   109
   :unsupported-extension               110
   :certificate-unobtainable-RESERVED   111
   :unrecognized-name                   112
   :bad-certificate-status-response     113
   :bad-certificate-hash-value-RESERVED 114
   :unknown-psk-identity                115
   :certificate-required                116
   :no-application-protocol             120})

(def st-alert-description st/st-ubyte)

(def st-alert
  (st/keys :level st-alert-level :description st-alert-description))

;;; b.3 handshake protocol

(def handshake-type-map
  {:hello-request-RESERVED        0
   :client-hello                  1
   :server-hello                  2
   :hello-verify-request-RESERVED 3
   :new-session-ticket            4
   :end-of-early-data             5
   :hello-retry-request-RESERVED  6
   :encrypted-extensions          8
   :certificate                   11
   :server-key-exchange-RESERVED  12
   :certificate-request           13
   :server-hello-done-RESERVED    14
   :certificate-verify            15
   :client-key-exchange-RESERVED  16
   :finished                      20
   :certificate-url-RESERVED      21
   :certificate-status-RESERVED   22
   :supplemental-data-RESERVED    23
   :key-update                    24
   :message-hash                  254})

(def st-handshake-type st/st-ubyte)

(def st-handshake
  (st/keys
   :msg-type st-handshake-type
   :msg-data (st/->st-var-bytes st-uint24)))

;;;; b.3.1 key exchange messages

(declare st-extension-list)
(declare st-cipher-suite-list)

(def st-client-hello
  (st/keys
   :legacy-version st-protocol-version ; tls12
   :random (st/->st-bytes 32)
   :legacy-session-id (st/->st-var-bytes st/st-ubyte)
   :cipher-suites st-cipher-suite-list
   :legacy-compression-methods st-compression-method-list
   :extensions st-extension-list))

(def st-server-hello
  (st/keys
   :legacy-version st-protocol-version ; tls12
   :random (st/->st-bytes 32)
   :legacy-session-id-echo (st/->st-var-bytes st/st-ubyte)
   :cipher-suites st-cipher-suite-list
   :legacy-compression-method st-compression-method ; null
   :extensions st-extension-list))

(declare st-extension-type)

(def st-extension
  (st/keys
   :extension-type st-extension-type
   :extension-data (st/->st-var-bytes st/st-ushort-be)))

(def st-extension-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-extension)))

(def extension-type-map
  {:server-name                            0
   :max-fragment-length                    1
   :status-request                         5
   :supported-groups                       10
   :signature-algorithms                   13
   :use-srtp                               14
   :heartbeat                              15
   :application-layer-protocol-negotiation 16
   :signed-certificate-timestamp           18
   :client-certificate-type                19
   :server-certificate-type                20
   :padding                                21
   :pre-shared-key                         41
   :early-data                             42
   :supported-versions                     43
   :cookie                                 44
   :psk-key-exchange-modes                 45
   :certificate-authorities                47
   :oid-filters                            48
   :post-handshake-auth                    49
   :signature-algorithms-cert              50
   :key-share                              51})

(def st-extension-type st/st-ushort-be)

(declare st-named-group)

(def st-key-share-entry
  (st/keys
   :group st-named-group
   :key-exchange (st/->st-var-bytes st/st-ushort-be)))

(def st-key-share-entry-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-key-share-entry)))

(def st-key-share-client-hello st-key-share-entry-list)
(def st-key-share-hello-retry-request st-named-group)
(def st-key-share-server-hello st-key-share-entry)

(def st-uncompressed-point-representation-p256
  (st/keys :legacy-form st/st-ubyte ; 4
           :points (st/coll-of 2 (st/->st-bytes 32))))

(def st-uncompressed-point-representation-p384
  (st/keys :legacy-form st/st-ubyte ; 4
           :points (st/coll-of 2 (st/->st-bytes 48))))

(def st-uncompressed-point-representation-p512
  (st/keys :legacy-form st/st-ubyte ; 4
           :points (st/coll-of 2 (st/->st-bytes 66))))

(def psk-key-exchange-mode-map
  {:psk-ke 0 :psk-dhe-ke 1})

(def st-psk-key-exchange-mode st/st-ubyte)
(def st-psk-key-exchange-mode-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-psk-key-exchange-mode)))

(def st-psk-key-exchange-modes st-psk-key-exchange-mode-list)

(def st-early-data-indication-new-session-ticket st/st-uint-be)
(def st-early-data-indication-client-hello st/st-null)
(def st-early-data-indication-encrypted-extensions st/st-null)

(def st-psk-identity
  (st/keys
   :identity st/st-ushort-be
   :obfuscated-ticket-age st/st-uint-be))

(def st-psk-identity-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-psk-identity)))

(def st-psk-binder-entry (st/->st-var-bytes st/st-ubyte))
(def st-psk-binder-entry-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-psk-binder-entry)))

(def st-offered-psks
  (st/keys
   :identities st-psk-identity-list
   :binders st-psk-binder-entry-list))

(def st-pre-shared-key-extension-client-hello st-offered-psks)
(def st-pre-shared-key-extension-server-hello st/st-ushort-be)

;;;;; b.3.1.1 version extension

(def st-supported-version-client-hello st-protocol-version-list)
(def st-supported-version-server-hello st-protocol-version)

;;;;; b.3.1.2 cookie extension

(def st-cookie (st/->st-var-bytes st/st-ushort-be))

;;;;; b.3.1.3 signature algorithm extension

(def signature-scheme-map
  {:rsa-pkcs1-sha256       0x0401
   :rsa-pkcs1-sha384       0x0501
   :rsa-pkcs1-sha512       0x0601
   :ecdsa-secp256r1-sha256 0x0403
   :ecdsa-secp384r1-sha384 0x0503
   :ecdsa-secp521r1-sha512 0x0603
   :rsa-pss-rsae-sha256    0x0804
   :rsa-pss-rsae-sha384    0x0805
   :rsa-pss-rsae-sha512    0x0806
   :ed25519                0x0807
   :ed448                  0x0808
   :rsa-pss-pss-sha256     0x0809
   :rsa-pss-pss-sha384     0x080a
   :rsa-pss-pss-sha512     0x080b
   :rsa-pkcs1-sha1         0x0201
   :ecdsa-sha1             0x0203})

(def st-signature-scheme st/unpack-short-be)
(def st-signature-scheme-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-signature-scheme)))

;;;;; b.3.1.4 supported groups extension

(def named-group-map
  {:secp256r1 0x0017
   :secp384r1 0x0018
   :secp521r1 0x0019
   :x25519    0x001d
   :x448      0x001e
   :ffdhe2048 0x0100
   :ffdhe3072 0x0101
   :ffdhe4096 0x0102
   :ffdhe6144 0x0103
   :ffdhe8192 0x0104})

(def st-named-group st/unpack-short-be)
(def st-named-group-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-named-group)))

;;;; b.3.2 server parameters messages

(def st-distinguished-name (st/->st-var-bytes st/st-ushort-be))
(def st-distinguished-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-distinguished-name)))

(def st-certificate-authorities-extension st-distinguished-name-list)

(def st-oid-filter
  (st/keys
   :certificate-extension-oid (st/->st-var-bytes st/st-ubyte)
   :certificate-extension-values (st/->st-var-bytes st/st-ushort-be)))

(def st-oid-filter-list
  (-> (st/->st-var-bytes st/unpack-short-be)
      (st/wrap-many-struct st-oid-filter)))

(def st-oid-filter-extension st-oid-filter-list)

(def st-post-handshake-auth st/st-null)

(def st-encrypted-extension st-extension-list)

(def st-certificate-request
  (st/keys
   :certificate-request-context (st/->st-var-bytes st/st-ubyte)
   :extensions st-extension-list))

;;;; b.3.3 authentication messages

(def certificate-type-map
  {:x509              0
   :open-pgp-RESERVED 1
   :raw-public-key    2})

(def st-certificate-type st/st-ubyte)

(def st-certificate-entry
  (st/keys
   :cert-data (st/->st-var-bytes st-uint24)
   :extensions st-extension-list))

(def st-certificate-entry-list
  (-> (st/->st-var-bytes st-uint24)
      (st/wrap-many-struct st-certificate-entry)))

(def st-certificate
  (st/keys
   :certificate-request-context (st/->st-var-bytes st/st-ubyte)
   :certificate-list st-certificate-entry-list))

(def st-certificate-verify
  (st/keys
   :algorithm st-signature-scheme
   :signature (st/->st-var-bytes st/st-ushort-be)))

;;;; b.3.4 ticket establishment

(def st-new-session-ticket
  (st/keys
   :ticket-lifetime st/st-uint-be
   :ticket-age-add st/st-uint-be
   :ticket-nonce (st/->st-var-bytes st/st-ubyte)
   :ticket (st/->st-var-bytes st/st-ushort-be)
   :extensions st-extension-list))

;;;; b.3.5 updating keys

(def st-end-of-early-data st/st-null)

(def key-update-request-map
  {:update-not-request 0 :update-requested 1})

(def st-key-update-request st/st-ubyte)

(def st-key-update st-key-update-request)

;;; b.4 cipher suites

(def cipher-suite-map
  {:tls-aes-128-gcm-sha256       0x1301
   :tls-aes-256-gcm-sha384       0x1302
   :tls-chacha20-poly1305-sha256 0x1303
   :tls-aes-128-ccm-sha256       0x1304
   :tls-aes-128-ccm-8-sha256     0x1305})

(def st-cipher-suite st/st-ushort-be)
(def st-cipher-suite-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-cipher-suite)))

;;; 6066.3 server name indication

(def name-type-map
  {:host-name 0})

(def st-name-type st/st-ubyte)

(def st-host-name (-> (st/->st-var-bytes st/st-ushort-be) st/wrap-str))

(def st-server-name-host
  (st/keys
   :name-type st-name-type ; host-name
   :name st-host-name))

;;; 7301.3.1 the alpn extension

(def st-protocol-name (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str))
(def st-protocol-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-protocol-name)))
