;;;; package.lisp --- Package definition for CFFI bindings to libkeystone.so
;;;;
;;;; Copyright (C) 2020 GrammaTech, Inc.
;;;;
;;;; This code is licensed under the MIT license. See the LICENSE file
;;;; in the project root for license terms.
;;;;
;;;; This project is sponsored by the Office of Naval Research, One
;;;; Liberty Center, 875 N. Randolph Street, Arlington, VA 22203 under
;;;; contract # N68335-17-C-0700.  The content of the information does
;;;; not necessarily reflect the position or policy of the Government
;;;; and no official endorsement should be inferred.
(defpackage :keystone
  (:use :common-lisp :cffi)
  (:import-from :static-vectors
                :with-static-vector
                :static-vector-pointer)
  (:export
   ;; Types
   :size-t
   :ks-engine
   ;; Enumerations
   :ks-arch
   :ks-mode
   :ks-err
   :ks-opt-type
   :ks-opt-value
   ;; Functions
   :ks-version
   :ks-arch_supported
   :ks-open
   :ks-close
   :ks-errno
   :ks-strerror
   :ks-option
   :ks-asm
   :ks-free))
