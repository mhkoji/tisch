(defpackage :tisch
  (:use :cl))
(in-package :tisch)

(defvar *client-version*
  "SSH-2.0-tisch_0.0.0")

(defmacro with-conntected-stream ((stream host port) &body body)
  `(usocket:with-client-socket (socket ,stream ,host ,port
                                       :element-type '(unsigned-byte 8))
     ,@body))

(defmacro with-client ((client host port) &body body)
  `(with-conntected-stream (stream ,host ,port)
     (let ((,client (tisch.client::make-client
                     :stream stream
                     :version *client-version*)))
       ,@body)))

;;;

(defun run (username password)
  (with-client (client "localhost" 22)
    (let ((server-version
           (tisch.client::exchange-version client)))
      (print server-version)
      (let ((client-kexinit
             (tisch.msg::make-kexinit
              :cookie #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
              :kex-algorithms (list "diffie-hellman-group14-sha256")
              :server-host-key-algorithms (list "rsa-sha2-256")
              :encryption-algorithms-client-to-server (list "aes128-ctr")
              :encryption-algorithms-server-to-client (list "aes128-ctr")
              :mac-algorithms-client-to-server (list "hmac-sha1")
              :mac-algorithms-server-to-client (list "hmac-sha1")
              :compression-algorithms-client-to-server (list "none")
              :compression-algorithms-server-to-client (list "none")
              :languages-client-to-server nil
              :languages-server-to-client nil
              :first-kex-packet-follows nil)))
        (tisch.client::send-msg client client-kexinit)
        (let ((server-kexinit
               (tisch.client::recv-msg client)))
          (print server-kexinit)
          (let ((modp tisch.dh::*modp-2048*))
            (destructuring-bind (e x)
                (tisch.dh::calculate-e modp)
              (tisch.client::send-msg
               client
               (tisch.msg::make-kexdh-init :e e))
              (let* ((server-kexdh-reply
                      (tisch.client::recv-msg client))
                     (f
                      (tisch.msg::kexdh-reply-f server-kexdh-reply))
                     (signature
                      (tisch.msg::kexdh-reply-signature-of-h
                       server-kexdh-reply))
                     (certificates
                      (tisch.msg::kexdh-reply-host-key-and-certificates
                       server-kexdh-reply)))
                (print server-kexdh-reply)
                (let* ((K
                        (tisch.dh::calculate-K modp f x))
                       (exchange-hash
                        (tisch.dh::exchange-hash
                         :V-C *client-version*
                         :V-S server-version
                         :I-C (tisch.transport::msg->payload client-kexinit)
                         :I-S (tisch.transport::msg->payload server-kexinit)
                         :K-S (tisch.msg::kexdh-reply-host-key-and-certificates-octets
                               server-kexdh-reply)
                         :e e
                         :f f
                         :K K)))
                  (print (list K exchange-hash))
                  (tisch.dh::verify signature
                                    certificates
                                    exchange-hash)
                  (tisch.client::send-msg
                   client (tisch.msg::make-newkeys))
                  (print
                   (tisch.client::recv-msg client))

                  (let* ((ek
                          (tisch.dh::build-encryption-keys
                           K exchange-hash exchange-hash))
                         (cipher-client-to-server
                          (tisch.cipher::make-aes128-ctr
                           (tisch.dh::encryption-keys-encryption-key-client-to-server ek)
                           (tisch.dh::encryption-keys-initial-iv-client-to-server ek)))
                         (cipher-server-to-client
                          (tisch.cipher::make-aes128-ctr
                           (tisch.dh::encryption-keys-encryption-key-server-to-client ek)
                           (tisch.dh::encryption-keys-initial-iv-server-to-client ek)))
                         (hmac-client-to-server
                          (tisch.cipher::make-hmac-sha1
                           (tisch.dh::encryption-keys-integrity-key-client-to-server ek)))
                         (hmac-server-to-client
                          (tisch.cipher::make-hmac-sha1
                           (tisch.dh::encryption-keys-integrity-key-server-to-client ek))))
                    (tisch.client::send-msg-encrypted
                     client cipher-client-to-server hmac-client-to-server
                     (tisch.msg::make-service-request
                      :service-name "ssh-userauth"))

                    (print
                     (tisch.client::recv-msg-encrypted
                      client cipher-server-to-client hmac-server-to-client))

                    (tisch.client::send-msg-encrypted
                     client cipher-client-to-server hmac-client-to-server
                     (tisch.msg::make-userauth-request-password
                      :user-name username
                      :service-name "ssh-connection"
                      :password password))

                    ;; 52
                    (print
                     (tisch.client::recv-packet-encrypted
                      client cipher-server-to-client hmac-server-to-client))

                    (tisch.client::send-msg-encrypted
                     client cipher-client-to-server hmac-client-to-server
                     (tisch.msg::make-channel-open-session
                      :sender-channel 1
                      :initial-window-size 40000
                      :maximum-packet-size 32678))

                    ;; 80
                    (print
                     (tisch.client::recv-packet-encrypted
                      client cipher-server-to-client hmac-server-to-client))

                    (let ((channel-open-confirmation
                           (tisch.client::recv-msg-encrypted
                            client cipher-server-to-client hmac-server-to-client)))
                      (print channel-open-confirmation)

                      (tisch.client::send-msg-encrypted
                       client cipher-client-to-server hmac-client-to-server
                       (tisch.msg::make-channel-request-exec
                        :recipient-channel
                        (tisch.msg::channel-open-confirmation-sender-channel
                         channel-open-confirmation)
                        :want-reply t
                        :command "ls"))

                      ;; 93
                      (print
                       (tisch.client::recv-packet-encrypted
                        client cipher-server-to-client hmac-server-to-client))

                      ;; 99
                      (print
                       (tisch.client::recv-packet-encrypted
                        client cipher-server-to-client hmac-server-to-client))

                      ;; 94
                      (print
                       (tisch.client::recv-packet-encrypted
                        client cipher-server-to-client hmac-server-to-client))

                      ))))))))))
  (values))
