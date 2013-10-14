(ns clj-http.test.conn-mgr
  (:use [clojure.test]
        [clj-http.test.core :only [run-server]])
  (:require [clj-http.conn-mgr :as conn-mgr]
            [clj-http.core :as core]
            [clj-http.client :as client]
            [ring.adapter.jetty :as ring])
  (:import (java.security KeyStore)
           (org.apache.http.conn.ssl SSLSocketFactory)
           (org.apache.http.impl.conn BasicClientConnectionManager)))

(def client-ks "test-resources/client-keystore")
(def client-ks-pass "keykey")
(def secure-request {:request-method :get :uri "/"
                     :server-port 18084 :scheme :https
                     :keystore client-ks :keystore-pass client-ks-pass
                     :trust-store client-ks :trust-store-pass client-ks-pass
                     :server-name "localhost" :insecure? true})

(defn secure-handler [req]
  (if (nil? (:ssl-client-cert req))
    {:status 403}
    {:status 200}))

(defn mock-digest-auth-handler [req]
  (if (contains? (:headers req) "authorization")
    ;; if there is an authorization header, pass it through in the response body
    {:status 200, :body (get (:headers req) "authorization")}
    {:status 401, :headers {"WWW-Authenticate" "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""}}))

(deftest load-keystore
  (let [ks (conn-mgr/get-keystore "test-resources/keystore" nil "keykey")]
    (is (instance? KeyStore ks))
    (is (> (.size ks) 0))))

(deftest keystore-scheme-factory
  (let [sr (conn-mgr/get-keystore-scheme-registry
            {:keystore client-ks :keystore-pass client-ks-pass
             :trust-store client-ks :trust-store-pass client-ks-pass})
        socket-factory (.getSchemeSocketFactory (.get sr "https"))]
    (is (instance? SSLSocketFactory socket-factory))))

(deftest ^{:integration true} ssl-client-cert-get
  (let [t (doto (Thread. #(ring/run-jetty secure-handler
                                          {:port 18083 :ssl-port 18084
                                           :ssl? true
                                           :keystore "test-resources/keystore"
                                           :key-password "keykey"
                                           :client-auth :want})) .start)]
    ;; wait for jetty to start up completely
    (Thread/sleep 3000)
    (let [resp (core/request {:request-method :get :uri "/get"
                              :server-port 18084 :scheme :https
                              :insecure? true :server-name "localhost"})]
      (is (= 403 (:status resp))))
    (let [resp (core/request secure-request)]
      (is (= 200 (:status resp))))))

(deftest ^{:integration true} t-closed-conn-mgr-for-as-stream
  (run-server)
  (let [shutdown? (atom false)
        cm (proxy [BasicClientConnectionManager] []
             (shutdown []
               (reset! shutdown? true)))]
    (try
      (core/request {:request-method :get :uri "/timeout"
                     :server-port 18080 :scheme :http
                     :server-name "localhost"
                     ;; timeouts forces an exception being thrown
                     :socket-timeout 1
                     :conn-timeout 1
                     :connection-manager cm
                     :as :stream})
      (is false "request should have thrown an exception")
      (catch Exception e))
    (is @shutdown? "Connection manager has been shut down")))

(deftest ^{:integration true} digest-authentication
  (let [t (doto (Thread. #(ring/run-jetty mock-digest-auth-handler
                                          {:port 18083})) .start)]
    ;; wait for jetty to start up completely
    (Thread/sleep 3000)
    (let [resp (client/get "http://localhost:18083/get" {
      :digest-auth  ["user" "pass"]})]
      (is (= 200 (:status resp))))
    ))

(deftest ^{:integration true} digest-authentication-reuse
  "make sure that once authenticated, the same digest is reused
  within the same connection."
  (let [t (doto (Thread. #(ring/run-jetty mock-digest-auth-handler
                                          {:port 18083})) .start)]
    ;; wait for jetty to start up completely
    (Thread/sleep 3000)
    (let [cm (conn-mgr/make-reusable-conn-manager {:timeout 10 :threads 1})]
      ;; make the first request
      (client/get "http://localhost:18083/get" {
        :connection-manager cm
        :digest-auth  ["user" "pass"]})
      ;; make the second request, reusing the connection stored in cm
      (let [resp2 (client/get "http://localhost:18083/get" {
        :connection-manager cm
        :digest-auth  ["user" "pass"]})]
        ;; The request counter should have incremented.  This tells us
        ;; that the same connection was reused, and that the request
        ;; did not have to be re-authenticated.
        (is (re-find #"nc=00000002" (:body resp2)))))) "The incremented request counter was not found.")
      
