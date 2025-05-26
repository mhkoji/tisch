(defpackage :tisch.client
  (:use :cl))
(in-package :tisch.client)

(defstruct client stream version)

(defun exchange-version (client)
  (tisch.transport::exchange-version (client-stream client)
                                     (client-stream client)
                                     (client-version client)))

(defun send-msg-keyinit (client keyinit)
  (let ((stream (client-stream client)))
    (let ((payload (flexi-streams:with-output-to-sequence (seq-stream)
                     (tisch.transport::write-msg-keyinit seq-stream keyinit))))
      (tisch.transport::write-packet stream payload))
    (force-output stream)))

(defun recv-msg-keyinit (client)
  (let ((octets (tisch.transport::read-packet (client-stream client))))
    (flexi-streams:with-input-from-sequence (seq-stream octets)
      (tisch.transport::read-msg-keyinit seq-stream))))
