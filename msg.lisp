(defpackage :tisch.msg
  (:use :cl))
(in-package :tisch.msg)

(defstruct kexinit
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
  host-key-and-certificates-octets
  f
  signature-of-H)

(defstruct newkeys)

(defstruct service-request
  service-name)

(defstruct service-accept
  service-name)

(defclass userauth-request ()
  ((user-name
    :initarg :user-name
    :reader userauth-request-user-name)
   (service-name
    :initarg :service-name
    :reader userauth-request-service-name)))

(defclass userauth-request-password (userauth-request)
  ((password
    :initarg :password
    :reader userauth-request-password-password)))

(defun make-userauth-request-password (&key user-name service-name password)
  (make-instance 'userauth-request-password
                 :user-name user-name
                 :service-name service-name
                 :password password))

(defstruct channel-open-session
  sender-channel
  initial-window-size
  maximum-packet-size)

(defstruct ssh-rsa
  e
  n)

(defstruct signature-rsa-sha2-256
  blob)

(defstruct packet
  length
  payload
  padding)

(let ((minimum-padding-length 4))
  (defun create-packet (payload block-size)
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
