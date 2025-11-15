(defpackage :tisch.transport
  (:use :cl)
  (:shadow :read-byte
           :write-byte
           :write-string))
(in-package :tisch.transport)

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

(defun write-uint32 (octet-stream integer)
  (let ((seq (make-array 4 :element-type '(unsigned-byte 8))))
    (loop for i from 3 downto 0
          for byte = (logand (ash integer (* -8 i)) #xFF)
          do (setf (aref seq (- 3 i)) byte))
    (write-sequence seq octet-stream)))

(defun read-uint32 (octet-stream)
  (let ((seq (make-array 4 :element-type '(unsigned-byte 8))))
    (read-sequence seq octet-stream)
    (loop for i from 3 downto 0
          for byte = (aref seq (- 3 i))
          sum (ash byte (* 8 i)))))

(defun write-uint (octet-stream uint count)
  (let ((seq (make-array count :element-type '(unsigned-byte 8)))
        (end-index (1- count)))
    (loop for i from 0 to end-index
          for byte = (logand (ash uint (* -8 i)) #xFF)
          do (setf (aref seq (- end-index i)) byte))
    (write-sequence seq octet-stream)))

(defun read-uint (octet-stream count)
  (let ((seq (make-array count :element-type '(unsigned-byte 8)))
        (end-index (1- count)))
    (read-sequence seq octet-stream)
    ;; todo: negative value
    (loop for i from 0 to end-index
          for byte = (aref seq (- end-index i))
          sum (ash byte (* 8 i)))))

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
    (read-uint octet-stream count)))

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


(defun write-msg-keyinit (octet-stream keyinit)
  (do-write octet-stream
    (:byte      20)
    (:bytes     (tisch.msg::keyinit-cookie keyinit))
    (:name-list (tisch.msg::keyinit-kex-algorithms keyinit))
    (:name-list (tisch.msg::keyinit-server-host-key-algorithms keyinit))
    (:name-list (tisch.msg::keyinit-encryption-algorithms-client-to-server keyinit))
    (:name-list (tisch.msg::keyinit-encryption-algorithms-server-to-client keyinit))
    (:name-list (tisch.msg::keyinit-mac-algorithms-client-to-server keyinit))
    (:name-list (tisch.msg::keyinit-mac-algorithms-server-to-client keyinit))
    (:name-list (tisch.msg::keyinit-compression-algorithms-client-to-server keyinit))
    (:name-list (tisch.msg::keyinit-compression-algorithms-server-to-client keyinit))
    (:name-list (tisch.msg::keyinit-languages-client-to-server keyinit))
    (:name-list (tisch.msg::keyinit-languages-server-to-client keyinit))
    (:boolean   (tisch.msg::keyinit-first-kex-packet-follows keyinit))
    (:uint32    0)))

(defun read-msg-keyinit (octet-stream)
  (with-reader (r octet-stream)
    (let ((keyinit
           (tisch.msg::make-keyinit
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
      keyinit)))

(defun write-msg-kexdh-init (octet-stream kexdh-init)
  (do-write octet-stream
    (:byte  30)
    (:mpint (tisch.msg::kexdh-init-e kexdh-init))))

(defun read-msg-kexdh-reply (octet-stream)
  (with-reader (r octet-stream)
    (tisch.msg::make-kexdh-reply
     :host-key-and-certificates (r :string)
     :f                         (r :mpint)
     :signature-of-h            (r :string))))


(defgeneric write-msg (msg octet-stream))

(defmethod write-msg ((msg tisch.msg::keyinit)
                      octet-stream)
  (write-msg-keyinit octet-stream msg))

(defmethod write-msg ((msg tisch.msg::kexdh-init)
                      octet-stream)
  (write-msg-kexdh-init octet-stream msg))

(defun msg->payload (msg)
  (flexi-streams:with-output-to-sequence (octet-stream)
    (write-msg msg octet-stream)))


(defun read-msg (octet-stream)
  (let ((type (read-byte octet-stream)))
    (cond ((= type 20)
           (read-msg-keyinit octet-stream))
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
