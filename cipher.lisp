(defpackage :tisch.cipher
  (:use :cl)
  (:import-from :ironclad
                :encrypt
                :decrypt))
(in-package :tisch.cipher)

(defun make-aes128-ctr (key iv)
  (ironclad:make-cipher :aes
                        :key key
                        :mode :ctr
                        :initialization-vector iv))
