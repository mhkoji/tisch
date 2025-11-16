;; rfc3447
(defpackage :tisch.pkcs
  (:use :cl))
(in-package :tisch.pkcs)

(defun mod-expt (base power divisor)
  (labels ((rec (product base power)
             (cond ((= power 0)
                    product)
                   ((evenp power)
                    (rec product
                         (mod (* base base) divisor)
                         (ash power -1)))
                   (t
                    (rec (mod (* product base) divisor)
                         base
                         (1- power))))))
    (rec 1 base power)))

;;;

(defun os2ip (octets)
  (let ((ret 0)
        (length (length octets)))
    (loop for i from 0 below length
          for val = (ash (aref octets i)
                         (* 8 (- length i 1)))
          do (setf ret (logior ret val)))
    ret))

(defun i2osp (uint length)
  (let ((seq (make-array length)))
    (loop for i from (1- length) downto 0
          for value = uint then (ash value -8)
          do (setf (aref seq i) (logand value #xFF)))
    seq))

(defgeneric hasher-identifier (hasher))
(defgeneric hasher-hash (hasher message))

(defun rsassa-pkcs1-v1-5-compare (message
                                  encoded-message-from-signature
                                  hasher)
  (assert (= (aref encoded-message-from-signature 0) 0))
  (assert (= (aref encoded-message-from-signature 1) 1))
  (let ((i 2))
    (loop for val = (aref encoded-message-from-signature i)
          while (/= val 0)
          do (progn
               (assert (= val #xFF))
               (incf i)))
    (incf i) ;; skip 0
    (let ((identifier (hasher-identifier hasher)))
      (loop for v1 across identifier
            for v2 = (aref encoded-message-from-signature i)
            do (progn
                 (assert (= v1 v2))
                 (incf i))))
    (let ((em1 (hasher-hash hasher message))
          (em2 (subseq encoded-message-from-signature i)))
      (assert (equalp em1 em2)))))

(defun rsassa-pkcs1-v1-5-verify (hasher message signature e n)
  (rsassa-pkcs1-v1-5-compare
   message
   (let ((s (os2ip signature)))
     (let ((m (mod-expt s e n)))
       (i2osp m (length signature))))
   hasher))
