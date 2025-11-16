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

(defun emsa-pkcs1-v1-5-digest-info (em)
  ;; EM = 0x00 || 0x01 || PS || 0x00 || T
  (assert (= (aref em 0) 0))
  (assert (= (aref em 1) 1))
  (let ((pos (position #x00 em :start 2)))
    (loop for i from 2 below pos
          do (assert (= (aref em i) #xFF)))
    ;; skip 0
    (subseq em (1+ pos))))

;; 8.2.2 Signature verification operation
;;    RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)
(defun rsassa-pkcs1-v1-5-verify (hasher message signature e n)
  (let ((digest-info (emsa-pkcs1-v1-5-digest-info
                      (let ((s (os2ip signature)))
                        (let ((m (mod-expt s e n)))
                          (i2osp m (length signature)))))))
    (let ((i 0))
      (let ((identifier (hasher-identifier hasher)))
        (loop for v1 across identifier
              for v2 = (aref digest-info i)
              do (progn
                   (assert (= v1 v2))
                   (incf i))))
      (let ((em1 (hasher-hash hasher message))
            (em2 (subseq digest-info i)))
        (assert (equalp em1 em2))))))
