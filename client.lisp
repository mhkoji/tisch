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

(defun send-packet (client packet)
  ;; (format *debug-io* "Written: ~A ~%" packet)
  (let ((stream (client-stream client)))
    (tisch.transport::write-packet stream packet)
    (force-output stream)))

(defun read-packet (client)
  (let ((packet (tisch.transport::read-packet (client-stream client))))
    ;; (format *debug-io* "Read: ~A ~%" packet)
    packet))

(defun msg->packet (msg &key (block-size 8))
  (tisch.msg::create-packet
   (tisch.transport::msg->payload msg) block-size))

(defun packet->msg (packet)
  (tisch.transport::payload->msg
   (tisch.msg::packet-payload packet)))


(defun send-msg (client msg)
  (incf (client-send-sequence-number client))
  (send-packet client (msg->packet msg)))

(defun send-msg-encrypted (client cipher hmac msg)
  (with-accessors ((stream client-stream)
                   (sequence-number client-send-sequence-number)) client
    (tisch.transport::write-packet-encrypted
     stream cipher hmac (msg->packet msg :block-size 16) sequence-number)
    (force-output stream)
    (incf sequence-number))
  (values))

(defun recv-msg (client)
  (incf (client-recv-sequence-number client))
  (packet->msg (read-packet client)))

(defun recv-msg-encrypted (client cipher hmac)
  (with-accessors ((stream client-stream)
                   (sequence-number client-recv-sequence-number)) client
    (let ((packet (tisch.transport::read-packet-encrypted
                   stream cipher hmac sequence-number)))
      (incf sequence-number)
      (packet->msg packet))))
