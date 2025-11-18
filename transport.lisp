(defpackage :tisch.transport
  (:use :cl)
  (:shadow :read-byte
           :write-byte
           :write-string))
(in-package :tisch.transport)

(defun sequence->uint (seq length)
  (let ((end-index (1- length)))
    (loop for i from 0 to end-index
          for byte = (aref seq (- end-index i))
          sum (ash byte (* 8 i)))))

(defun uint->sequence (uint length)
  (let ((seq (make-array length :element-type '(unsigned-byte 8)))
        (end-index (1- length)))
    (loop for i from 0 to end-index
          for byte = (logand (ash uint (* -8 i)) #xFF)
          do (setf (aref seq (- end-index i)) byte))
    seq))

(defun write-byte (octet-stream value)
  (cl:write-byte value octet-stream))

(defun read-byte (octet-stream)
  (cl:read-byte octet-stream nil nil))

(defun write-bytes (octet-stream seq)
  (write-sequence seq octet-stream))

(defun read-bytes (octet-stream length)
  (let ((seq (make-array length :element-type '(unsigned-byte 8))))
    (read-sequence seq octet-stream)
    seq))

(defun write-boolean (octet-stream value)
  (write-byte octet-stream (if value 1 0)))

(defun read-boolean (octet-stream)
  (= (read-byte octet-stream) 1))

(defun write-uint32 (octet-stream uint)
  (write-sequence (uint->sequence uint 4) octet-stream))

(defun read-uint32 (octet-stream)
  (let ((seq (make-array 4 :element-type '(unsigned-byte 8))))
    (read-sequence seq octet-stream)
    (sequence->uint seq 4)))

(defun write-uint (octet-stream uint count)
  (write-sequence (uint->sequence uint count) octet-stream))

(defun read-uint (octet-stream count)
  (let ((seq (make-array count :element-type '(unsigned-byte 8))))
    (read-sequence seq octet-stream)
    (sequence->uint seq count)))

(defun write-string (octet-stream octets)
  (write-uint32 octet-stream (length octets))
  (write-sequence octets octet-stream))

(defun read-string (octet-stream)
  (let ((length (read-uint32 octet-stream)))
    (let ((seq (make-array length :element-type '(unsigned-byte 8))))
      (read-sequence seq octet-stream)
      seq)))

(defun write-name-list (octet-stream string-list)
  (let ((string (format nil "~{~a~^,~}" string-list)))
    (let ((octets (babel:string-to-octets string :encoding :utf-8)))
      (write-string octet-stream octets))))

(defun read-name-list (octet-stream)
  (let ((octets (read-string octet-stream)))
    (let ((string (babel:octets-to-string octets :encoding :utf-8)))
      (cl-ppcre:split "," string))))

(defun write-mpint-positive (octet-stream int count)
  (write-uint octet-stream count 4)
  (write-uint octet-stream int count))

(defun write-mpint (octet-stream int)
  (if (<= 0 int)
      (let ((count (loop for i from 0
                         when (= 0 (ash int (* -8 i)))
                           return i)))
        (if (logbitp (1- (* 8 count)) int)
            (write-mpint-positive octet-stream int (1+ count))
            (write-mpint-positive octet-stream int count)))
      (destructuring-bind (count . inverted)
          (loop for i from 1
                for val = #x100 then (ash val 8)
                for inverted = (+ val int)
                when (and (< 0 inverted)
                          (logbitp (1- (* 8 i)) inverted))
                  return (cons i inverted))
        (write-mpint-positive octet-stream inverted count))))

(defun read-mpint (octet-stream)
  (let ((count (read-uint32 octet-stream)))
    ;; todo: negative value
    (read-uint octet-stream count)))

(defun read-ssh-rsa (octet-stream)
  (tisch.msg::make-ssh-rsa
   :e (read-mpint octet-stream)
   :n (read-mpint octet-stream)))

(defun write-packet (octet-stream packet)
  (write-uint32 octet-stream (tisch.msg::packet-length packet))
  (write-byte   octet-stream (tisch.msg::packet-padding-length packet))
  (write-bytes  octet-stream (tisch.msg::packet-payload packet))
  (write-bytes  octet-stream (tisch.msg::packet-padding packet)))

(defun read-packet (octet-stream)
  (let* ((packet-length (read-uint32 octet-stream))
         (packet        (read-bytes  octet-stream packet-length)))
    (let ((padding-length (aref packet 0)))
      (tisch.msg::make-packet
       :length packet-length
       :payload (subseq packet 1 (- packet-length padding-length))
       :padding (subseq packet (- packet-length padding-length))))))


(defmacro do-write (stream &rest clauses)
  `(progn
     ,@(mapcar (lambda (clause)
                 (destructuring-bind (key &rest args) clause
                   `(,(ecase key
                        (:byte 'write-byte)
                        (:bytes 'write-bytes)
                        (:name-list 'write-name-list)
                        (:boolean 'write-boolean)
                        (:string 'write-string)
                        (:uint32 'write-uint32)
                        (:mpint 'write-mpint))
                     ,stream ,@args)))
               clauses)))

(defmacro with-reader ((reader stream) &body body)
  `(macrolet ((,reader (key &rest args)
                ,(list 'list*
                       '(ecase key
                         (:byte 'read-byte)
                         (:bytes 'read-bytes)
                         (:uint32 'read-uint32)
                         (:mpint 'read-mpint)
                         (:string 'read-string)
                         (:name-list 'read-name-list)
                         (:boolean 'read-boolean))
                       (list 'quote stream)
                       'args)))
     ,@body))


(defun write-msg-kexinit (octet-stream kexinit)
  (do-write octet-stream
    (:byte      20)
    (:bytes     (tisch.msg::kexinit-cookie kexinit))
    (:name-list (tisch.msg::kexinit-kex-algorithms kexinit))
    (:name-list (tisch.msg::kexinit-server-host-key-algorithms kexinit))
    (:name-list (tisch.msg::kexinit-encryption-algorithms-client-to-server kexinit))
    (:name-list (tisch.msg::kexinit-encryption-algorithms-server-to-client kexinit))
    (:name-list (tisch.msg::kexinit-mac-algorithms-client-to-server kexinit))
    (:name-list (tisch.msg::kexinit-mac-algorithms-server-to-client kexinit))
    (:name-list (tisch.msg::kexinit-compression-algorithms-client-to-server kexinit))
    (:name-list (tisch.msg::kexinit-compression-algorithms-server-to-client kexinit))
    (:name-list (tisch.msg::kexinit-languages-client-to-server kexinit))
    (:name-list (tisch.msg::kexinit-languages-server-to-client kexinit))
    (:boolean   (tisch.msg::kexinit-first-kex-packet-follows kexinit))
    (:uint32    0)))

(defun read-msg-kexinit (octet-stream)
  (with-reader (r octet-stream)
    (let ((kexinit
           (tisch.msg::make-kexinit
            :cookie                                  (r :bytes 16)
            :kex-algorithms                          (r :name-list)
            :server-host-key-algorithms              (r :name-list)
            :encryption-algorithms-client-to-server  (r :name-list)
            :encryption-algorithms-server-to-client  (r :name-list)
            :mac-algorithms-client-to-server         (r :name-list)
            :mac-algorithms-server-to-client         (r :name-list)
            :compression-algorithms-client-to-server (r :name-list)
            :compression-algorithms-server-to-client (r :name-list)
            :languages-client-to-server              (r :name-list)
            :languages-server-to-client              (r :name-list)
            :first-kex-packet-follows                (r :boolean)))
          (reserved (r :uint32)))
      (assert (= reserved 0))
      kexinit)))

(defun write-msg-kexdh-init (octet-stream kexdh-init)
  (do-write octet-stream
    (:byte  30)
    (:mpint (tisch.msg::kexdh-init-e kexdh-init))))

(defun write-msg-newkeys (octet-stream)
  (do-write octet-stream
    (:byte 21)))

(defun write-msg-service-request (octet-stream msg)
  (do-write octet-stream
    (:byte 5)
    (:string (babel:string-to-octets
              (tisch.msg::service-request-service-name msg)))))


(defun read-certificates (octet-stream)
  (let ((format (babel:octets-to-string (read-string octet-stream))))
    (cond ((string= format "ssh-rsa")
           (read-ssh-rsa octet-stream))
          (t
           (error "unknown format: ~A" format)))))

(defun read-signature (octet-stream)
  (let ((format (babel:octets-to-string (read-string octet-stream))))
    (cond ((string= format "rsa-sha2-256")
           (tisch.msg::make-signature-rsa-sha2-256
            :blob (read-string octet-stream)))
          (t
           (error "unknown format: ~A" format)))))

(defun read-msg-kexdh-reply (octet-stream)
  (let* ((host-key-and-certificates-octets (read-string octet-stream)))
    (tisch.msg::make-kexdh-reply
     :host-key-and-certificates
     (flexi-streams:with-input-from-sequence
         (s host-key-and-certificates-octets)
       (read-certificates s))
     :host-key-and-certificates-octets
     host-key-and-certificates-octets
     :f (read-mpint octet-stream)
     :signature-of-h
     (let ((octets (read-string octet-stream)))
       (flexi-streams:with-input-from-sequence (s octets)
         (read-signature s))))))

(defgeneric write-msg (msg octet-stream))

(defmethod write-msg ((msg tisch.msg::kexinit)
                      octet-stream)
  (write-msg-kexinit octet-stream msg))

(defmethod write-msg ((msg tisch.msg::kexdh-init)
                      octet-stream)
  (write-msg-kexdh-init octet-stream msg))

(defmethod write-msg ((msg tisch.msg::newkeys)
                      octet-stream)
  (write-msg-newkeys octet-stream))

(defmethod write-msg ((msg tisch.msg::service-request)
                      octet-stream)
  (write-msg-service-request octet-stream msg))


(defun msg->payload (msg)
  (flexi-streams:with-output-to-sequence (octet-stream)
    (write-msg msg octet-stream)))


(defun read-msg (octet-stream)
  (let ((type (read-byte octet-stream)))
    (cond ((= type 20)
           (read-msg-kexinit octet-stream))
          ((= type 21)
           (tisch.msg::make-newkeys))
          ((= type 31)
           (read-msg-kexdh-reply octet-stream))
          (t
           (error "invalid type: ~A" type)))))

(defun payload->msg (payload)
  (flexi-streams:with-input-from-sequence (octet-stream payload)
    (read-msg octet-stream)))


(defun send-client-version (octet-stream client-version)
  (let ((octets (babel:string-to-octets
                 (format nil "~A~A~A" client-version #\Return #\Linefeed))))
    (write-sequence octets octet-stream)
    (force-output octet-stream)))

(defun recv-server-version (octet-stream)
  (let ((stream (flexi-streams:make-flexi-stream
                 octet-stream
                 :external-format
                 (flexi-streams:make-external-format
                  :iso-8859-1
                  :eol-style :crlf))))
    (loop for line = (read-line stream stream)
          when (cl-ppcre:scan "^SSH-" line) return line)))

(defun exchange-version (octet-input-stream octet-output-stream client-version)
  (send-client-version octet-input-stream client-version)
  (recv-server-version octet-output-stream))
