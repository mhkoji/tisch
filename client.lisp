(defpackage :tisch.client
  (:use :cl))
(in-package :tisch.client)

(defstruct client stream version)

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

(defun msg->packet (msg)
  (tisch.msg::create-packet
   (tisch.transport::msg->payload msg)))

(defun packet->msg (packet)
  (tisch.transport::payload->msg
   (tisch.msg::packet-payload packet)))


(defun send-msg (client msg)
  (send-packet client (msg->packet msg)))

(defun recv-msg (client)
  (packet->msg (read-packet client)))
