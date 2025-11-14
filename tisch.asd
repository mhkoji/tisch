(asdf:defsystem :tisch
  :serial t
  :components ((:file "msg")
               (:file "transport")
               (:file "client")
               (:file "dh")
               (:file "tisch"))
  :depends-on (:ironclad
               :usocket
               :flexi-streams
               :cl-ppcre
               :babel))
