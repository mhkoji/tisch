(defpackage :tisch.cipher
  (:use :cl)
  (:import-from :ironclad
                :encrypt-message
                :decrypt-message))
(in-package :tisch.cipher)

(defun make-aes128-ctr (key iv)
  (ironclad:make-cipher :aes
                        :key key
                        :mode :ctr
                        :initialization-vector iv))

(defstruct hmac
  key name)

(defun make-hmac-sha1 (key)
  (make-hmac :key key :name :sha1))

(defun hmac-update-and-digest (hmac octets)
  (let ((hmac-impl (ironclad:make-hmac (hmac-key hmac)
                                       (hmac-name hmac))))
    (ironclad:update-hmac hmac-impl octets)
    (ironclad:hmac-digest hmac-impl)))
