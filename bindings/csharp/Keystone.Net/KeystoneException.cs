using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Keystone
{
    /// <summary>
    ///   Represents an error encountered while encoding one or more instructions.
    /// </summary>
    public sealed class KeystoneException : Exception
    {
        /// <summary>
        ///   Gets the value that represents the encountered error.
        /// </summary>
        public KeystoneError Error { get; }

        internal KeystoneException(string message, KeystoneError error) : base(message + '.')
        {
            Debug.Assert(error != KeystoneError.KS_ERR_OK);
            
            Error = error;
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return $"{Message}: {Engine.ErrorToString(Error)}.";
        }
    }
}
