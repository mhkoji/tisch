(defpackage :tisch.client
  (:use :cl))
(in-package :tisch.client)

(defstruct client stream version)

(defun exchange-version (client)
  (tisch.transport::exchange-version (client-stream client)
                                     (client-stream client)
                                     (client-version client)))

(defun write-packet (client packet)
  ;; (format *debug-io* "Written: ~A ~%" packet)
  (let ((stream (client-stream client)))
    (tisch.transport::write-packet stream packet)
    (force-output stream)))

(defun read-packet (client)
  (let ((packet (tisch.transport::read-packet (client-stream client))))
    ;; (format *debug-io* "Read: ~A ~%" packet)
    packet))

(defun send-msg-keyinit (client keyinit)
  (let ((packet (tisch.msg::create-packet
                 (tisch.transport::msg-keyinit->payload keyinit))))
    (write-packet client packet)))

(defun recv-msg (client)
  (let ((packet (read-packet client)))
    (let ((payload (tisch.msg::packet-payload packet)))
      (tisch.transport::payload->msg payload))))
