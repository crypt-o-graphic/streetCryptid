using System.Security.AccessControl;
using System.Security.Principal;
using StreetCryptid.Repeater.Core;

namespace StreetCryptid.Repeater.Service;

/// <summary>
/// The service's state lives under ProgramData, where every local user may create folders. So any
/// of <c>streetCryptid</c>, <c>streetCryptid\Repeater</c> or its <c>.incoming</c> staging directory
/// can exist before the installer first runs, made by someone else: owned by them (an owner can
/// always rewrite the DACL, so they could read the identity key once it lands), holding a
/// <c>secret.key</c> they chose (a repeater identity whose private key they know, which
/// <see cref="StateMigration"/> would swap into place), or a junction that sends the key somewhere
/// they can read. Taking ownership of such a directory is not enough: its contents and any handle
/// opened before the DACL changed are still theirs. So a directory we did not make is moved aside
/// whole, under a name that says why, and a fresh one is made in its place.
/// </summary>
internal static class StateDirectory
{
    private const string UntrustedSuffix = ".untrusted-";

    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static SecurityIdentifier ServiceSid() =>
        (SecurityIdentifier)new NTAccount(ServiceLayout.Account).Translate(typeof(SecurityIdentifier));

    /// <summary>
    /// Owned by Administrators; SYSTEM, Administrators and the service, inherited by everything
    /// beneath, and nothing inherited from ProgramData (whose ACL lets Users create and CREATOR
    /// OWNER take full control).
    /// </summary>
    public static DirectorySecurity Security(SecurityIdentifier service)
    {
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(true, false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { LocalSystem, Administrators, service })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit,
                PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// False when <paramref name="path"/>, or with <paramref name="deep"/> anything beneath it, is a
    /// reparse point (junction, symlink, mount point) or is owned by anyone but SYSTEM,
    /// Administrators, the service or <paramref name="installer"/>. The installer's own account is
    /// trusted because under the "default owner: object creator" policy what an elevated admin
    /// creates is owned by that admin rather than by Administrators. A missing path is trusted.
    /// </summary>
    public static bool IsTrusted(string path, SecurityIdentifier service, SecurityIdentifier? installer, bool deep)
    {
        FileSystemInfo info;
        try
        {
            // Read without following: a link is judged as the link, never as what it points to.
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
            info = attributes.HasFlag(FileAttributes.Directory) ? new DirectoryInfo(path) : new FileInfo(path);
        }
        catch (FileNotFoundException) { return true; }
        catch (DirectoryNotFoundException) { return true; }
        FileSystemSecurity security = info switch
        {
            DirectoryInfo directory => directory.GetAccessControl(AccessControlSections.Owner),
            FileInfo file => file.GetAccessControl(AccessControlSections.Owner),
            _ => throw new InvalidOperationException(),
        };
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !(owner == LocalSystem || owner == Administrators || owner == service || owner == installer))
            return false;
        if (!deep || info is not DirectoryInfo dir) return true;
        foreach (var entry in dir.EnumerateFileSystemInfos())
            if (!IsTrusted(entry.FullName, service, installer, true)) return false;
        return true;
    }

    /// <summary>
    /// Move <paramref name="path"/> aside to <c>path.untrusted-&lt;id&gt;</c> when it is not
    /// trusted; the renamed directory is the record of what was found. Renaming a junction renames
    /// the link, never its target. True when something was moved.
    /// </summary>
    public static bool SetAsideIfUntrusted(string path, SecurityIdentifier service, SecurityIdentifier? installer,
        bool deep)
    {
        if (IsTrusted(path, service, installer, deep)) return false;
        string aside = path.TrimEnd(Path.DirectorySeparatorChar) + UntrustedSuffix + Guid.NewGuid().ToString("N");
        if (File.GetAttributes(path).HasFlag(FileAttributes.Directory)) Directory.Move(path, aside);
        else File.Move(path, aside);
        return true;
    }

    /// <summary>
    /// After a migration: the state directory gets <see cref="Security"/> explicitly (so a root
    /// loosened by hand does not loosen the identity), and everything in it is owned by
    /// Administrators, so nothing in it keeps an owner who could rewrite its DACL.
    /// </summary>
    public static void Secure(string path, SecurityIdentifier service)
    {
        var directory = new DirectoryInfo(path);
        directory.SetAccessControl(Security(service));
        foreach (var entry in directory.EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
        {
            switch (entry)
            {
                case DirectoryInfo child:
                {
                    var owner = new DirectorySecurity();
                    owner.SetOwner(Administrators);
                    child.SetAccessControl(owner);
                    break;
                }
                case FileInfo file:
                {
                    var owner = new FileSecurity();
                    owner.SetOwner(Administrators);
                    file.SetAccessControl(owner);
                    break;
                }
            }
        }
    }
}
