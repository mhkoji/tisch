(defpackage :tisch.client
  (:use :cl))
(in-package :tisch.client)

(defstruct client
  stream
  version
  (send-sequence-number 0)
  (recv-sequence-number 0))

(defun exchange-version (client)
  (tisch.transport::exchange-version (client-stream client)
                                     (client-stream client)
                                     (client-version client)))

(defmacro do-client-send ((stream sequence-number client) &body body)
  `(with-accessors ((,stream client-stream)
                    (,sequence-number client-send-sequence-number)) ,client
     ,@body
     (force-output ,stream)
     (incf ,sequence-number)
     (values)))

(defmacro do-client-recv ((stream sequence-number client) &body body)
  (let ((g (gensym)))
    `(with-accessors ((,stream client-stream)
                      (,sequence-number client-recv-sequence-number)) ,client
       (let ((,g (progn ,@body)))
         (incf ,sequence-number)
         ,g))))


(defun msg->packet (msg &key (block-size 8))
  (tisch.msg::create-packet
   (tisch.transport::msg->payload msg) block-size))

(defun packet->msg (packet)
  (tisch.transport::payload->msg
   (tisch.msg::packet-payload packet)))


(defun send-msg (client msg)
  (do-client-send (stream sequence-number client)
    (tisch.transport::write-packet stream (msg->packet msg))))

(defun send-msg-encrypted (client cipher hmac msg)
  (do-client-send (stream sequence-number client)
    (tisch.transport::write-packet-encrypted
     stream cipher hmac (msg->packet msg :block-size 16) sequence-number)))

(defun recv-msg (client)
  (packet->msg
   (do-client-recv (stream sequence-number client)
     (tisch.transport::read-packet stream))))

(defun recv-packet-encrypted (client cipher hmac)
  (do-client-recv (stream sequence-number client)
    (tisch.transport::read-packet-encrypted
     stream cipher hmac sequence-number)))

(defun recv-msg-encrypted (client cipher hmac)
  (packet->msg (recv-packet-encrypted client cipher hmac)))
