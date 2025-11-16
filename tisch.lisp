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

(defun run ()
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
          (let ((dh tisch.dh::*modp-2048*))
            (destructuring-bind (e x)
                (tisch.dh::calculate-e dh)
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
                (let ((exchange-hash
                       (tisch.dh::exchange-hash
                        :V-C *client-version*
                        :V-S server-version
                        :I-C (tisch.transport::msg->payload client-kexinit)
                        :I-S (tisch.transport::msg->payload server-kexinit)
                        :K-S (tisch.msg::kexdh-reply-host-key-and-certificates-octets
                              server-kexdh-reply)
                        :e e
                        :f f
                        :K (tisch.dh::calculate-K dh f x))))
                  (tisch.dh::verify signature
                                    certificates
                                    exchange-hash))))))))
    (values)
    #+nil
    (loop for byte = (read-byte
                      (tisch.client::client-stream client))
          while byte do (print byte))))
