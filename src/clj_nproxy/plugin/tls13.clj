(ns clj-nproxy.plugin.tls13
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.context :as tls13-ctx])
  (:import [java.io BufferedInputStream BufferedOutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defn wrap
  "Wrap tls13 on stream."
  [{is :input-stream os :output-stream} context]
  (let [acontext (loop [context context]
                   (let [{:keys [stage send-bytes]} context]
                     (if (seq send-bytes)
                       (do
                         (run! (partial st/write os) send-bytes)
                         (st/flush os)
                         (recur (dissoc context :send-bytes)))
                       (if (= stage :connected)
                         (atom context)
                         (let [{:keys [type content]} (st/read-struct tls13-st/st-record is)]
                           (recur (tls13-ctx/recv-record context type content)))))))
        ;; TODO verify certificate
        read-fn (fn []
                  (let [{:keys [recv-bytes read-close?]} @acontext]
                    (if (seq recv-bytes)
                      (let [b (apply b/cat recv-bytes)]
                        (swap! acontext update :recv-bytes #(vec (drop (count recv-bytes) %)))
                        (if-not (zero? (b/length b))
                          b
                          (recur)))
                      (when-not read-close?
                        (let [{:keys [type content]} (st/read-struct tls13-st/st-record is)]
                          (swap! acontext tls13-ctx/recv-record type content)
                          (recur))))))
        write-fn (fn [b]
                   (when-not (zero? (b/length b))
                     (swap! acontext tls13-ctx/send-data b)
                     (let [{:keys [send-bytes]} @acontext]
                       (when (seq send-bytes)
                         (run! (partial st/write os) send-bytes)
                         (st/flush os)))))
        close-fn (fn []
                   (swap! acontext tls13-ctx/send-close-notify)
                   (let [{:keys [send-bytes]} @acontext]
                     (when (seq send-bytes)
                       (run! (partial st/write os) send-bytes)
                       (st/flush os))
                     (st/close os)))]
    {:acontext acontext
     :input-stream (BufferedInputStream. (st/read-fn->input-stream read-fn #(st/close is)))
     :output-stream (BufferedOutputStream. (st/write-fn->output-stream write-fn close-fn))}))
