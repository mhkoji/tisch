(defpackage :tisch.msg
  (:use :cl))
(in-package :tisch.msg)

(defstruct keyinit
  cookie
  kex-algorithms
  server-host-key-algorithms
  encryption-algorithms-client-to-server
  encryption-algorithms-server-to-client
  mac-algorithms-client-to-server
  mac-algorithms-server-to-client
  compression-algorithms-client-to-server
  compression-algorithms-server-to-client
  languages-client-to-server
  languages-server-to-client
  first-kex-packet-follows)
