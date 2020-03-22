;;;; test.lisp --- Tests for CFFI bindings to libkeystone.so
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
(defpackage :keystone/test
  (:use :common-lisp :cffi :keystone :stefil)
  (:import-from :uiop :nest)
  (:export :test))
(in-package :keystone/test)

(defsuite test)
(in-suite test)

(deftest ks-asm-original-example ()
  (nest
   (let ((arch :x86) (mode :32)
         (code "INC ecx; DEC edx")))
   (is)
   (string= #.(format nil "\"INC ecx; DEC edx\" = 41 4A ~%~
                             Compiled: 2 bytes, statements: 2~%"))
   (with-output-to-string (*standard-output*))
   (with-foreign-object (engine 'ks-engine))
   (with-foreign-object (encode '(:pointer :unsigned-char)))
   (with-foreign-object (size 'size-t))
   (with-foreign-object (count 'size-t)
     (assert (eql :ok (ks-open arch mode engine)) (engine)
             "Failed to open Keystone engine. ~a" (ks-errno engine))
     (assert (eql :ok (ks-asm (mem-ref engine 'ks-engine)
                              code
                              0
                              encode
                              size
                              count))
             (engine code)
             "Failed to disassemble given code. ~s"
             (ks-strerror (ks-errno engine)))
     (format t "~S = " code)
     (dotimes (n (mem-ref size 'size-t))
       (format t "~x " (mem-aref (mem-ref encode :pointer) :unsigned-char n)))
     (format t "~%Compiled: ~d bytes, statements: ~a~%"
             (mem-ref size 'size-t)
             (mem-ref count 'size-t))
     (ks-free (mem-ref encode :pointer))
     (mem-ref engine 'ks-engine))))
