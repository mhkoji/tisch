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

(defun make-hmac-sha1 (key)
  (ironclad:make-hmac key :sha1))

(defun hmac-update-and-digest (hmac octets)
  (ironclad:update-hmac hmac octets)
  (ironclad:hmac-digest hmac))
