using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace StreetCryptid.Repeater.Service;

internal enum Signature
{
    /// <summary>No Authenticode signature at all (every unsigned preview).</summary>
    Unsigned,
    /// <summary>Signed, and WinVerifyTrust accepts the signature and its chain.</summary>
    Valid,
    /// <summary>Signed, but the signature, the chain or a revocation check failed.</summary>
    Invalid,
}

/// <summary>
/// WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2), no UI, revocation checked for the whole
/// chain, and the subject of the certificate that signed it — read from the signature WinVerifyTrust
/// just verified, not parsed out of the file a second time.
/// </summary>
internal static unsafe class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly IntPtr NoWindow = new(-1);
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const uint UiNone = 2, RevokeWholeChain = 1, ChoiceFile = 1;
    private const uint StateActionVerify = 1, StateActionClose = 2;
    private const uint RevocationCheckChainExcludeRoot = 0x80, DisableMd2Md4 = 0x2000;

    public static Signature Check(string path, out string? signer)
    {
        signer = null;
        fixed (char* file = path)
        {
            var info = new WinTrustFileInfo { Size = (uint)sizeof(WinTrustFileInfo), FilePath = file };
            var data = new WinTrustData
            {
                Size = (uint)sizeof(WinTrustData),
                UiChoice = UiNone,
                RevocationChecks = RevokeWholeChain,
                UnionChoice = ChoiceFile,
                File = &info,
                StateAction = StateActionVerify,
                ProvFlags = RevocationCheckChainExcludeRoot | DisableMd2Md4,
            };
            Guid action = GenericVerifyV2;
            int result = WinVerifyTrust(NoWindow, &action, &data);
            try
            {
                if (result == TrustENoSignature) return Signature.Unsigned;
                if (result != 0) return Signature.Invalid;
                IntPtr provider = WTHelperProvDataFromStateData(data.StateData);
                IntPtr first = provider == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
                IntPtr leaf = first == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvCertFromChain(first, 0);
                if (leaf == IntPtr.Zero) return Signature.Invalid;
                // CRYPT_PROVIDER_CERT: a DWORD cbStruct, then PCCERT_CONTEXT pCert (pointer-aligned).
                IntPtr context = *(IntPtr*)((byte*)leaf + IntPtr.Size);
                if (context == IntPtr.Zero) return Signature.Invalid;
#pragma warning disable SYSLIB0057
                using var certificate = new X509Certificate2(context);
#pragma warning restore SYSLIB0057
                signer = certificate.Subject;
                return Signature.Valid;
            }
            finally
            {
                data.StateAction = StateActionClose;
                WinVerifyTrust(NoWindow, &action, &data);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint Size;
        public char* FilePath;
        public IntPtr File;
        public Guid* KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public WinTrustFileInfo* File;
        public uint StateAction;
        public IntPtr StateData;
        public char* UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll")]
    private static extern int WinVerifyTrust(IntPtr window, Guid* action, WinTrustData* data);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signer, int counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certificate);
}
