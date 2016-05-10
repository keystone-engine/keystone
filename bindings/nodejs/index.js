var ref = require('ref'),
    ffi = require('ffi'),
    consts = require('./consts'),
    extend = require('util')._extend

var ks_engine = 'void',
    ks_enginePtr = ref.refType(ks_engine),
    ks_enginePtrPtr = ref.refType(ks_enginePtr),
    ks_arch = 'int',
    ks_err = 'int',
    ks_opt_type = 'int',
    uintPtr = ref.refType('uint'),
    ucharPtr = ref.refType('uchar'),
    ucharPtrPtr = ref.refType(ucharPtr),
    size_tPtr = ref.refType('size_t'),
    stringPtr = ref.refType('string')

var Keystone = ffi.Library('libkeystone', {
  'ks_version': [ 'uint', [ uintPtr, uintPtr ] ],
  'ks_arch_supported': [ 'bool', [ ks_arch ] ],
  'ks_open': [ ks_err, [ ks_arch, 'int', ks_enginePtrPtr ] ],
  'ks_close': [ ks_err, [ ks_enginePtr ] ],
  'ks_errno': [ 'int', [ ks_enginePtr ] ],
  'ks_strerror': [ 'string', [ ks_err ] ],
  'ks_option': [ ks_err, [ ks_enginePtr, ks_opt_type, 'size_t' ] ],
  'ks_asm': [ 'int', [ ks_enginePtr, 'string', 'uint64', ucharPtrPtr, size_tPtr, size_tPtr ] ],
  'ks_free': [ 'void', [ 'pointer' ] ]
})

function KsError(message, errno, count) {
  this.message = message
  this.errno = errno
  this.count = count
}

function Ks(arch, mode) {
  var _ks = ref.alloc(ks_enginePtr),
      err = Keystone.ks_open(arch, mode, _ks)

  if (err !== consts.ERR_OK) {
    this._ks = null
    throw new KsError('Error: failed on ks_open()')
  }

  this._ks = _ks.deref()
  

  this.__defineGetter__('errno', function() {
    return Keystone.ks_errno(this._ks)
  })

  this.__defineSetter__('syntax', function(value) {
    this.set_option(consts.OPT_SYNTAX, value)
  })
}

Ks.prototype.asm = function(code, addr) {
  var encoding = ref.alloc('uchar *'),
      size = ref.alloc('size_t'),
      count = ref.alloc('size_t'),
      err, msg 

  if (Keystone.ks_asm(this._ks, code, addr || 0, encoding, size, count) !== consts.ERR_OK) {
    err = this.errno
    msg = Keystone.ks_strerror(err)
    throw new KsError(msg, err, count.deref())
  }

  return {
    encoding: ref.reinterpret(encoding.deref(), size.deref(), 0),
    count: count.deref()
  }
}

Ks.prototype.close = function() {
  Keystone.ks_close(this._ks)
  this._ks = null
}

Ks.prototype.set_option = function(type, value) {
  var err = Keystone.ks_option(this._ks, type, value)
  if (err != consts.ERR_OK) {
    throw new KsError(Keystone.ks_strerror(err), err)
  }
}

module.exports.Ks = Ks

module.exports.is_arch_supported = function(arch) {
  return Keystone.ks_arch_supported(arch)
}

module.exports.__defineGetter__('version', function() {
  var version = Keystone.ks_version(null, null)
  return {
    major: version >> 8,
    minor: version & 255
  }
})
extend(module.exports, consts)
