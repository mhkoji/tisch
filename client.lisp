(defpackage :tisch.client
  (:use :cl))
(in-package :tisch.client)

(defstruct client stream version)

(defun exchange-version (client)
  (tisch.transport::exchange-version (client-stream client)
                                     (client-stream client)
                                     (client-version client)))

(defun send-msg-keyinit (client keyinit)
  (let ((packet (tisch.msg::create-packet
                 (tisch.transport::msg-keyinit->payload keyinit))))
    (let ((stream (client-stream client)))
      (tisch.transport::write-packet stream packet)
      (force-output stream))))

(defun recv-msg-keyinit (client)
  (let ((packet (tisch.transport::read-packet (client-stream client))))
    (tisch.transport::payload->msg-keyinit (tisch.msg::packet-payload packet))))
