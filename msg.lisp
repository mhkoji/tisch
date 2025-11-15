(defpackage :tisch.msg
  (:use :cl))
(in-package :tisch.msg)

(defstruct keyinit
  cookie
  kex-algorithms
  server-host-key-algorithms
  encryption-algorithms-client-to-server
  encryption-algorithms-server-to-client
  mac-algorithms-client-to-server
  mac-algorithms-server-to-client
  compression-algorithms-client-to-server
  compression-algorithms-server-to-client
  languages-client-to-server
  languages-server-to-client
  first-kex-packet-follows)

(defstruct kexdh-init
  e)

(defstruct kexdh-reply
  host-key-and-certificates
  f
  signature-of-H)

(defstruct packet
  length
  payload
  padding)

(let ((block-size 8)
      (minimum-padding-length 4))
  (defun create-packet (payload)
    (let* ((payload-length (length payload))
           (reminder (rem (+ 1 4 payload-length)
                          block-size))
           (lacking-length (- block-size reminder))
           (padding-length (if (<= minimum-padding-length lacking-length)
                               lacking-length
                               (+ lacking-length block-size))))
      (make-packet :length (+ payload-length padding-length 1)
                   :payload payload
                   :padding (make-array padding-length)))))

(defun packet-padding-length (packet)
  (logand (length (packet-padding packet)) #xFF))
