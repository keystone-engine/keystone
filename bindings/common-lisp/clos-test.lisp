;;;; test.lisp --- Tests for CLOS interface to the Keystone assembler
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
(defpackage :keystone/clos-test
  (:use :gt :cffi :keystone :keystone/clos :stefil)
  (:export :test))
(in-package :keystone/clos-test)
(in-readtable :curry-compose-reader-macros)

(defsuite test)
(in-suite test)

(deftest version-returns-two-numbers ()
  (is (multiple-value-call [{every #'numberp} #'list] (version))))

(deftest simple-asm ()
  (is (equalp #(#x41 #x4A)
              (asm (make-instance 'keystone-engine :architecture :x86 :mode :32)
                   "INC ecx; DEC edx"))))
