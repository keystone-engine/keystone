VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CAsmResult"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Option Explicit

'Keystone Assembly Engine bindings for VB6
'Contributed by FireEye FLARE Team
'Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License: Apache 2.0
'Copyright: FireEye 2017

'NOTE: the VB code was built and tested against the latest binary release: Keystone 0.9.1
'      I will enabled the symbol resolver once it makes it into the stable release

Public errMsg As String
Public lastErr As ks_err
Public size As Long
Public count As Long
Public source As String
Public arch As ks_arch
Public mode As ks_mode
Public syntax As ks_opt_type

Private b() As Byte

Property Get hadErr() As Boolean
    If Len(errMsg) > 0 Or lastErr <> 0 Then hadErr = True
End Property
    
Property Get result() As Byte()
    result = b
End Property

Friend Property Let result(buf() As Byte)
    b = buf
End Property

