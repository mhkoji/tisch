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

(defun write-string (octet-stream string)
  (write-sequence (babel:string-to-octets string :encoding :utf-8)
                  octet-stream))

(defun read-string (octet-stream length)
  (let ((seq (make-array length :element-type '(unsigned-byte 8))))
    (read-sequence seq octet-stream)
    (babel:octets-to-string seq :encoding :utf-8)))

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

(defun write-name-list (octet-stream string-list)
  (let ((string (format nil "~{~a~^,~}" string-list)))
    (write-uint32 octet-stream (length string))
    (write-string octet-stream string)))

(defun read-name-list (octet-stream)
  (let ((length (read-uint32 octet-stream)))
    (if (= length 0)
        nil
        (let ((string (read-string octet-stream length)))
          (cl-ppcre:split "," string)))))

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


(defmacro with-first-arg (defs first-arg &body body)
  `(macrolet ,(mapcar (lambda (def)
                        (list (car def) '(&rest args)
                              (list 'list*
                                    (list 'quote (cadr def))
                                    (list 'quote first-arg)
                                    'args)))
               defs)
     ,@body))

(defun write-msg-keyinit (octet-stream keyinit)
  (with-first-arg ((.name-list write-name-list)
                   (.byte      write-byte)
                   (.bytes     write-bytes)
                   (.uint32    write-uint32)
                   (.boolean   write-boolean)) octet-stream
    (.byte      20)
    (.bytes     (tisch.msg::keyinit-cookie keyinit))
    (.name-list (tisch.msg::keyinit-kex-algorithms keyinit))
    (.name-list (tisch.msg::keyinit-server-host-key-algorithms keyinit))
    (.name-list (tisch.msg::keyinit-encryption-algorithms-client-to-server keyinit))
    (.name-list (tisch.msg::keyinit-encryption-algorithms-server-to-client keyinit))
    (.name-list (tisch.msg::keyinit-mac-algorithms-client-to-server keyinit))
    (.name-list (tisch.msg::keyinit-mac-algorithms-server-to-client keyinit))
    (.name-list (tisch.msg::keyinit-compression-algorithms-client-to-server keyinit))
    (.name-list (tisch.msg::keyinit-compression-algorithms-server-to-client keyinit))
    (.name-list (tisch.msg::keyinit-languages-client-to-server keyinit))
    (.name-list (tisch.msg::keyinit-languages-server-to-client keyinit))
    (.boolean   (tisch.msg::keyinit-first-kex-packet-follows keyinit))
    (.uint32    0)))

(defun read-msg-keyinit (octet-stream)
  (with-first-arg ((.name-list read-name-list)
                   (.byte      read-byte)
                   (.bytes     read-bytes)
                   (.uint32    read-uint32)
                   (.boolean   read-boolean)) octet-stream
    (assert (= (.byte) 20))
  (tisch.msg::make-keyinit
   :cookie                                  (.bytes 16)
   :kex-algorithms                          (.name-list)
   :server-host-key-algorithms              (.name-list)
   :encryption-algorithms-client-to-server  (.name-list)
   :encryption-algorithms-server-to-client  (.name-list)
   :mac-algorithms-client-to-server         (.name-list)
   :mac-algorithms-server-to-client         (.name-list)
   :compression-algorithms-client-to-server (.name-list)
   :compression-algorithms-server-to-client (.name-list)
   :languages-client-to-server              (.name-list)
   :languages-server-to-client              (.name-list)
   :first-kex-packet-follows                (.boolean))))

(defun msg-keyinit->payload (keyinit)
  (flexi-streams:with-output-to-sequence (octet-stream)
    (write-msg-keyinit octet-stream keyinit)))

(defun payload->msg-keyinit (payload)
  (flexi-streams:with-input-from-sequence (octet-stream payload)
    (read-msg-keyinit octet-stream)))


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
