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
    (tisch.client::exchange-version
     client)
    (tisch.client::send-msg-keyinit
     client
     (tisch.msg::make-keyinit
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
      :first-kex-packet-follows nil))
    (print (tisch.client::recv-msg client))
    (tisch.client::send-msg-kexdh-init
     client
     (tisch.dh::gen tisch.dh::*modp-2048*))
    (tisch.client::recv-msg client)
    #+nil
    (loop for byte = (read-byte
                      (tisch.client::client-stream client))
          while byte do (print byte))))
