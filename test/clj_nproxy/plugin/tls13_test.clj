(ns clj-nproxy.plugin.tls13-test
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.java.io :as io]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13 :as tls13]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto :as tls13-crypto]
            [clj-nproxy.plugin.tls13.context :as tls13-ctx]))

(defn read-resource
  [resource]
  (with-open [is (io/input-stream (io/resource resource))]
    (.readAllBytes is)))

(defonce cert (delay (tls13-crypto/bytes->cert (read-resource "resources/cert.der"))))
(defonce pri (delay (tls13-crypto/bytes->pri "Ed25519" (read-resource "resources/pri.der"))))

(deftest tls13-test
  (testing "handshake"
    (is (some? (st/sim-conn
                (fn [{is :input-stream os :output-stream}]
                  (let [{:keys [acontext]} (tls13/wrap is os (tls13-ctx/->client-context {:server-names ["test.local"] :application-protocols ["http/2" "http/1.1"]}))]
                    (assert (= (select-keys @acontext [:stage :cipher-suite :named-group :accept-server-name? :application-protocol])
                               {:stage :connected
                                :cipher-suite tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                                :named-group tls13-st/named-group-x25519
                                :accept-server-name? true
                                :application-protocol "http/1.1"}))))
                (fn [{is :input-stream os :output-stream}]
                  (let [{:keys [acontext]} (tls13/wrap is os (tls13-ctx/->server-context {:server-certificate-list [{:certificate @cert}] :server-private-key @pri :application-protocols ["http/1.1"]}))]
                    (assert (= (select-keys @acontext [:stage :cipher-suite :named-group :server-names :application-protocol])
                               {:stage :connected
                                :cipher-suite tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                                :named-group tls13-st/named-group-x25519
                                :server-names ["test.local"]
                                :application-protocol "http/1.1"})))))))))
