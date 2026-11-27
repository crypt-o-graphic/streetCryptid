using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using StreetCryptid.Repeater.Core;

namespace StreetCryptid.Repeater.Service;

/// <summary>
/// The unattended service update, run as LocalSystem by the SCM when the owner's app starts the
/// updater service with the version it just updated to. Without it, every app update ended with an
/// administrator prompt for the service's copy under Program Files.
///
/// What it trusts, in order: HTTPS to this project's GitHub releases and nowhere else (every
/// redirect is checked against <see cref="IsReleaseHost"/>); the archive's SHA-256 published beside
/// it (<see cref="ServiceLayout.ServiceArchiveChecksum"/>), which catches a damaged or swapped
/// archive but comes over the same channel, so it is no defence against the release itself being
/// replaced; and the Authenticode signer of the installed copy (<see cref="SignedLikeInstalled"/>):
/// once a signed service is installed, only executables signed by the same subject are taken. While
/// releases are unsigned previews the last check passes unsigned files, and the trust is the first
/// two. What a caller controls: only which version, and it must be newer than this one, so the
/// worst a caller can do is install a release we published early. It never reads anything from a
/// directory the person can write: the staging directory is under Program Files.
/// </summary>
internal static class Updater
{
    private const long MaxArchiveBytes = 256L * 1024 * 1024;
    private const long MaxChecksumBytes = 1024;
    private const int MaxRedirects = 5;
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(10);

    public static async Task<uint> RunAsync(string[] arguments, CancellationToken stop)
    {
        if (arguments is not [var requested] || !ReleaseVersion.TryParse(requested, out var target) ||
            !ReleaseVersion.TryParse(Program.Version, out var installed))
            return (uint)ServiceVerbResult.BadArguments;
        if (target.CompareTo(installed) <= 0) return (uint)ServiceVerbResult.NotNewer;

        string rid = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "win-arm64" : "win-x64";
        string staging = ServiceLayout.UpdateStagingDirectory;
        try
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, true);
            Directory.CreateDirectory(staging);
            string archive = Path.Combine(staging, ServiceLayout.ServiceArchive(rid));
            byte[] expected, actual;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
                timeout.CancelAfter(DownloadTimeout);
                using var client = CreateClient();
                expected = await FetchChecksumAsync(client,
                    new Uri(ServiceLayout.ServiceArchiveChecksumUrl(target, rid)), timeout.Token);
                actual = await DownloadAsync(client, new Uri(ServiceLayout.ServiceArchiveUrl(target, rid)), archive,
                    timeout.Token);
            }
            catch (Exception) when (!stop.IsCancellationRequested) { return (uint)ServiceVerbResult.DownloadFailed; }
            if (!CryptographicOperations.FixedTimeEquals(expected, actual)) return (uint)ServiceVerbResult.Failed;
            string unpacked = Path.Combine(staging, "files");
            if (!Unpack(archive, unpacked)) return (uint)ServiceVerbResult.Failed;
            if (!SignedLikeInstalled(unpacked)) return (uint)ServiceVerbResult.Failed;
            stop.ThrowIfCancellationRequested();
            return (uint)Installer.Replace(unpacked);
        }
        finally
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, true); }
            catch (Exception) { }
        }
    }

    /// <summary>
    /// The release host and GitHub's storage hosts it redirects a download to
    /// (<c>objects.githubusercontent.com</c>, <c>release-assets.githubusercontent.com</c>), over
    /// HTTPS on the default port. Nothing else, at any hop.
    /// </summary>
    private static bool IsReleaseHost(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort &&
        (uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
         uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase));

    private static HttpClient CreateClient()
    {
        // Redirects are followed by hand (GetAsync), so each hop's host is checked before it is asked.
        var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"streetCryptid-repeater-updater/{Program.Version}");
        return client;
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, Uri uri, CancellationToken cancellation)
    {
        for (int hop = 0; ; hop++)
        {
            if (!IsReleaseHost(uri)) throw new HttpRequestException($"Refusing {uri.Host}: not a release host.");
            var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellation);
            int status = (int)response.StatusCode;
            if (status is not (301 or 302 or 303 or 307 or 308))
            {
                try { response.EnsureSuccessStatusCode(); }
                catch { response.Dispose(); throw; }
                return response;
            }
            var location = response.Headers.Location;
            response.Dispose();
            if (location is null || hop >= MaxRedirects) throw new HttpRequestException("Bad redirect.");
            uri = location.IsAbsoluteUri ? location : new Uri(uri, location);
        }
    }

    /// <summary>The first field of a <c>sha256sum</c> line: 64 hex digits.</summary>
    private static async Task<byte[]> FetchChecksumAsync(HttpClient client, Uri uri, CancellationToken cancellation)
    {
        using var response = await GetAsync(client, uri, cancellation);
        if (response.Content.Headers.ContentLength > MaxChecksumBytes)
            throw new HttpRequestException("Checksum too large.");
        byte[] body = await response.Content.ReadAsByteArrayAsync(cancellation);
        if (body.Length > MaxChecksumBytes) throw new HttpRequestException("Checksum too large.");
        string[] fields = Encoding.ASCII.GetString(body).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length == 0 || fields[0].Length != 64) throw new HttpRequestException("Malformed checksum.");
        return Convert.FromHexString(fields[0]);
    }

    /// <summary>Writes the archive to <paramref name="path"/> and returns its SHA-256.</summary>
    private static async Task<byte[]> DownloadAsync(HttpClient client, Uri uri, string path,
        CancellationToken cancellation)
    {
        using var response = await GetAsync(client, uri, cancellation);
        if (response.Content.Headers.ContentLength > MaxArchiveBytes)
            throw new HttpRequestException("Release archive too large.");
        await using var body = await response.Content.ReadAsStreamAsync(cancellation);
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await body.ReadAsync(buffer, cancellation)) > 0)
        {
            total += read;
            if (total > MaxArchiveBytes) throw new HttpRequestException("Release archive too large.");
            hash.AppendData(buffer, 0, read);
            await file.WriteAsync(buffer.AsMemory(0, read), cancellation);
        }
        return hash.GetHashAndReset();
    }

    /// <summary>
    /// The new executables must be signed by whoever signed the running one. A signed install
    /// therefore never takes an unsigned or differently signed update — the downgrade an attacker
    /// who can replace a release asset would otherwise use. An unsigned install (every preview so
    /// far) takes unsigned files, but never ones whose signature fails to verify. The subject is
    /// compared, not the thumbprint, because short-lived signing certificates (Azure Trusted
    /// Signing's are valid for days) change thumbprint between releases and keep their subject.
    /// </summary>
    private static bool SignedLikeInstalled(string unpacked)
    {
        var installed = Authenticode.Check(Path.Combine(AppContext.BaseDirectory, ServiceLayout.ServiceExecutable),
            out string? pinned);
        foreach (string name in new[] { ServiceLayout.ServiceExecutable, ServiceLayout.HostExecutable })
        {
            var signature = Authenticode.Check(Path.Combine(unpacked, name), out string? signer);
            bool ok = installed switch
            {
                Signature.Valid => signature == Signature.Valid && signer == pinned,
                // A signed copy whose check fails now (revocation unreachable, say) pins nothing;
                // still take only a verified signature over it.
                Signature.Invalid => signature == Signature.Valid,
                _ => signature != Signature.Invalid,
            };
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>
    /// Only the service's own files, by name, from the archive's root; anything else in it is
    /// ignored, and an archive without the service and the host is refused.
    /// </summary>
    private static bool Unpack(string archive, string destination)
    {
        try
        {
            Directory.CreateDirectory(destination);
            using var zip = ZipFile.OpenRead(archive);
            foreach (string name in ServiceLayout.InstalledFiles)
            {
                var entry = zip.Entries.FirstOrDefault(e => e.FullName == name);
                if (entry is null || entry.Length > MaxArchiveBytes) continue;
                entry.ExtractToFile(Path.Combine(destination, name), false);
            }
            return File.Exists(Path.Combine(destination, ServiceLayout.ServiceExecutable)) &&
                   File.Exists(Path.Combine(destination, ServiceLayout.HostExecutable));
        }
        catch (Exception) { return false; }
    }
}
