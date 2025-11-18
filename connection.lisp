(defpackage :tisch.connection
  (:use :cl))
(in-package :tisch.connection)

(defstruct connection
  stream
  (send-sequence-number 0)
  (recv-sequence-number 0))

(defun exchange-version (conn version)
  (tisch.transport::exchange-version
   (connection-stream conn)
   (connection-stream conn)
   version))

(defun send-packet (conn packet)
  ;; (format *debug-io* "Written: ~A ~%" packet)
  (let ((stream (connection-stream conn)))
    (tisch.transport::write-packet stream packet)
    (force-output stream)))

(defun read-packet (conn)
  (let ((packet (tisch.transport::read-packet (connection-stream conn))))
    ;; (format *debug-io* "Read: ~A ~%" packet)
    packet))

(defun msg->packet (msg &key (block-size 8))
  (tisch.msg::create-packet
   (tisch.transport::msg->payload msg) block-size))

(defun packet->msg (packet)
  (tisch.transport::payload->msg
   (tisch.msg::packet-payload packet)))


(defun send-msg (conn msg)
  (incf (connection-send-sequence-number conn))
  (send-packet conn (msg->packet msg)))

(defun recv-msg (conn)
  (incf (connection-recv-sequence-number conn))
  (packet->msg (read-packet conn)))


(defun send-msg-encrypted (conn cipher hmac msg)
  (let ((octets-plain
         ;; Avoid TYPE-ERROR: The value is not of
         ;;   type (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*))
         (copy-seq
          (flexi-streams:with-output-to-sequence (out-stream)
            (tisch.transport::write-packet
             out-stream (msg->packet msg :block-size 16)))))
        (sequence-number
         (connection-send-sequence-number conn)))
    (let ((octets-encrypted
           (tisch.cipher::encrypt-message cipher octets-plain))
          (mac
           (tisch.cipher::hmac-update-and-digest
            hmac
            (copy-seq
             (flexi-streams:with-output-to-sequence (out-stream)
               (tisch.transport::write-uint32 out-stream sequence-number)
               (tisch.transport::write-bytes out-stream octets-plain))))))
      (let ((stream (connection-stream conn)))
        (tisch.transport::write-bytes stream octets-encrypted)
        (tisch.transport::write-bytes stream mac)
        (force-output stream))
      (incf (connection-send-sequence-number conn))))
  (values))

(defun read-packet-encrypted (stream cipher)
  (let ((packet-length (tisch.transport::sequence->uint
                        (tisch.cipher::decrypt-message
                         cipher
                         (tisch.transport::read-bytes stream 4))
                        4)))
    (let ((octets (tisch.cipher::decrypt-message
                   cipher
                   (tisch.transport::read-bytes stream packet-length))))
      (tisch.transport::parse-packet octets packet-length))))

(defun recv-msg-encrypted (conn cipher hmac)
  (let ((stream (connection-stream conn)))
    (let ((packet (read-packet-encrypted stream cipher))
          (mac (tisch.transport::read-bytes stream 20)))
      (let* ((sequence-number
              (connection-recv-sequence-number conn))
             (mac2
              (tisch.cipher::hmac-update-and-digest
               hmac
               (copy-seq
                (flexi-streams:with-output-to-sequence (out-stream)
                  (tisch.transport::write-uint32 out-stream sequence-number)
                  (tisch.transport::write-packet out-stream packet))))))
        (assert (equalp mac mac2)))
      (incf (connection-recv-sequence-number conn))
      (packet->msg packet))))
