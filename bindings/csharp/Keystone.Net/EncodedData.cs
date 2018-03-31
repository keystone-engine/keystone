namespace Keystone
{
    /// <summary>
    /// Defines an encoded instruction or group of instructions.
    /// </summary>
    public sealed class EncodedData
    {
        /// <summary>
        ///   Constructs the encoded data.
        /// </summary>
        internal EncodedData(byte[] buffer, uint statementCount, ulong address)
        {
            Buffer = buffer;
            Address = address;
            StatementCount = (int)statementCount;
        }

        /// <summary>
        ///   Gets the address of the first instruction for this operation.
        /// </summary>
        public ulong Address { get; }

        /// <summary>
        ///   Gets the result of an assembly operation.
        /// </summary>
        public byte[] Buffer { get; }

        /// <summary>
        ///   Gets the number of statements found.
        /// </summary>
        public int StatementCount { get; }
    }
}
