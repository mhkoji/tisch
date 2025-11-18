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

(defun encrypt-packet-octets (cipher octets)
  (ironclad:encrypt-message cipher octets)
  #+nil
  (let ((length (length octets)))
    (let ((octets-encrypted (make-array length
                                        :element-type '(unsigned-byte 8))))
      (tisch.cipher::encrypt cipher octets octets-encrypted)
      octets-encrypted)))

(defun msg->packet (msg &key (block-size 8))
  (tisch.msg::create-packet
   (tisch.transport::msg->payload msg) block-size))

(defun packet->msg (packet)
  (tisch.transport::payload->msg
   (tisch.msg::packet-payload packet)))


(defun send-msg (client msg)
  (send-packet client (msg->packet msg)))

(defun recv-msg (client)
  (packet->msg (read-packet client)))


(defun send-msg-encrypted (client cipher hmac msg)
  (let ((octets-plain
         ;; Avoid TYPE-ERROR: The value is not of
         ;;   type (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*))
         (copy-seq
          (flexi-streams:with-output-to-sequence (out-stream)
            (tisch.transport::write-packet
             out-stream (msg->packet msg :block-size 16)))))
        (sequence-number
         (client-send-sequence-number client)))
    (let ((octets-encrypted
           (encrypt-packet-octets cipher octets-plain))
          (mac
           (tisch.cipher::hmac-update-and-digest
            hmac
            (copy-seq
             (flexi-streams:with-output-to-sequence (out-stream)
               (tisch.transport::write-uint32 out-stream sequence-number)
               (tisch.transport::write-bytes out-stream octets-plain))))))
      (let ((stream (client-stream client)))
        (tisch.transport::write-bytes stream octets-encrypted)
        (tisch.transport::write-bytes stream mac)
        (force-output stream))
      (incf (client-send-sequence-number client))))
  (values))
