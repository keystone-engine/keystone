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
(eval-when (:load-toplevel :execute)
  (operate 'load-op 'trivial-features)
  (operate 'load-op 'cffi-grovel))

(use-package 'cffi-grovel)

(defsystem "keystone"
    :name "keystone"
    :author "GrammaTech"
    :licence "MIT"
    :description "Raw Common Lisp FFI interface to the Keystone assembler"
    :depends-on (:gt :cffi :static-vectors)
    :class :package-inferred-system
    :defsystem-depends-on (:asdf-package-system :cffi-grovel)
    :components ((:file "package")
                 (:cffi-grovel-file "grovel")
                 (:file "keystone"))
    :in-order-to ((test-op (test-op "keystone/test"))))

(defsystem "keystone/test"
  :author "GrammaTech"
  :licence "MIT"
  :description "Test the KEYSTONE package."
  :perform
  (test-op (o c) (symbol-call :keystone/test '#:test)))

(defsystem "keystone/clos"
  :author "GrammaTech"
  :licence "MIT"
  :description "Common Lisp CLOS interface to the Keystone assembler"
  :perform
  (test-op (o c) (symbol-call :keystone/clos-test '#:test)))

(defsystem "keystone/clos-test"
  :author "GrammaTech"
  :licence "MIT"
  :description "Test the KEYSTONE/CLOS package."
  :perform
  (test-op (o c) (symbol-call :keystone/clos-test '#:test)))
