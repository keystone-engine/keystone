namespace KeystoneNET
{
    /// <summary>
    /// Wrap the result of an assemble.
    /// </summary>
    public class KeystoneEncoded
    {
        /// <summary>
        /// Construct the object.
        /// </summary>
        /// <param name="buffer">Result of an assemble</param>
        /// <param name="statementCount">Number of statements found</param>
        /// <param name="address">Address of the first instruction</param>
        public KeystoneEncoded(byte[] buffer, uint statementCount, ulong address)
        {
            Buffer = buffer;
            StatementCount = statementCount;
            Address = address;
        }

        /// <summary>
        /// Address of the first instruction for this operation.
        /// </summary>
        public ulong Address { get; private set; }

        /// <summary>
        /// Result of an assemble operation.
        /// </summary>
        public byte[] Buffer { get; private set; }

        /// <summary>
        /// Number of statements found.
        /// </summary>
        public uint StatementCount { get; private set; }
    }
}
