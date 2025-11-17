(defpackage :tisch.cipher
  (:use :cl))
(in-package :tisch.cipher)

(defstruct aes
  key iv (mode :ctr))

(defun aes->cipher (aes)
  (ironclad:make-cipher :aes
                        :key (aes-key aes)
                        :mode (aes-mode aes)
                        :initialization-vector (aes-iv aes)))

(defun encrypt (aes octets)
  (ironclad:encrypt-message (aes->cipher aes) octets))

(defun decrypt (aes octets)
  (ironclad:decrypt-message (aes->cipher aes) octets))
