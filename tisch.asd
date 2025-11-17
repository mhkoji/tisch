(asdf:defsystem :tisch
  :serial t
  :components ((:file "cipher")
               (:file "pkcs")
               (:file "msg")
               (:file "transport")
               (:file "dh")
               (:file "client")
               (:file "tisch"))
  :depends-on (:ironclad
               :usocket
               :flexi-streams
               :cl-ppcre
               :babel))
