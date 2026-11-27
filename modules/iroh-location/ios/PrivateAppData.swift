import Foundation

/// Keeps location history out of iCloud and iTunes/Finder backups.
///
/// The Rust state root is excluded by `createNode` (`excludeFromBackup` in
/// `IrohLocationModule.swift`) and the replica lives in the temp dir, but two other places held
/// positions and were backed up by default:
///
/// - `Documents/SQLite`, expo-sqlite's default directory (`SQLiteModule.defaultDatabaseDirectory`).
///   `streetcryptid.social.db` holds the own trail, friends' last fixes and the pool with their
///   tickets; the exploration and telemetry-journal databases are location-derived too. A backup
///   is a copy of all of it on a server we do not control, restorable onto another phone.
/// - `UserDefaults`, which is always backed up, held the runtime's stop anchor, stop candidate,
///   unverified departure and visit arrival as coordinates. Those now live in
///   `RuntimeLocationStore`, below.
///
/// Runs on every launch once protected data is readable (`finishUnlockedLaunch`), because the flag
/// belongs to the directory: a directory deleted and re-created (a reinstall, expo-sqlite making it
/// on first open) comes back without it. Excluding a directory excludes everything under it, so
/// databases created before the flag lands are covered from the next backup on.
enum AppDataBackupExclusion {
  static func apply() {
    let fm = FileManager.default
    if let documents = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
      exclude(documents.appendingPathComponent("SQLite", isDirectory: true))
    }
    if let dir = RuntimeLocationStore.directory {
      exclude(dir)
    }
  }

  /// Create `dir` if needed and stamp it. Created rather than skipped when missing, because the
  /// first launch after install reaches here before JS has opened any database, and a directory
  /// that does not exist yet cannot carry the flag the databases are about to inherit.
  static func exclude(_ dir: URL) {
    var dir = dir
    do {
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try dir.setResourceValues(values)
    } catch {
      NSLog(
        "[iroh-location] could not exclude %@ from backup: %@", dir.path,
        error.localizedDescription)
    }
  }
}

/// The runtime's location-bearing launch state, kept out of `UserDefaults` because `UserDefaults`
/// is always backed up.
///
/// A UserDefaults-shaped key/value store over one plist in a backup-excluded Application Support
/// directory, written with the same protection class the defaults plist has
/// (`completeUntilFirstUserAuthentication`), so it is readable exactly when the rest of the
/// launch state is and `ProtectedDataGate` covers it unchanged.
///
/// Mutations are batched in memory and written by `commit()`, once per `persistState`.
///
/// Before the first unlock the file cannot be read and nothing is loaded; while unloaded every
/// write is dropped rather than replacing a file this process never saw — the same rule
/// `persistState` follows for `UserDefaults`. Loading is retried on the next access.
///
/// The first successful load migrates the old `UserDefaults` keys (`migratedPrefixes`) into the
/// file and, only once the file is written, deletes them from `UserDefaults`.
/// `@unchecked Sendable`: every member is guarded by `lock`.
final class RuntimeLocationStore: @unchecked Sendable {
  static let shared = RuntimeLocationStore()

  /// Every key the runtime used to keep in `UserDefaults` that carries a position, or belongs to
  /// one (`sc.bg.anchor.via`, `sc.bg.candidate.since`), so the group moves as a unit.
  static let migratedPrefixes = [
    "sc.bg.anchor.", "sc.bg.candidate.", "sc.bg.departed.", "sc.bg.visit_arrival.",
  ]

  static var directory: URL? {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
      .appendingPathComponent("sc-runtime", isDirectory: true)
  }

  private static var fileURL: URL? {
    directory?.appendingPathComponent("location-state.plist", isDirectory: false)
  }

  private let lock = NSLock()
  private var values: [String: Any] = [:]
  private var loaded = false
  private var dirty = false

  private init() {}

  // MARK: UserDefaults-shaped access

  func object(forKey key: String) -> Any? {
    lock.lock()
    defer { lock.unlock() }
    ensureLoaded()
    return values[key]
  }

  func double(forKey key: String) -> Double {
    (object(forKey: key) as? NSNumber)?.doubleValue ?? 0
  }

  func bool(forKey key: String) -> Bool {
    (object(forKey: key) as? NSNumber)?.boolValue ?? false
  }

  func string(forKey key: String) -> String? {
    object(forKey: key) as? String
  }

  func set(_ value: Double, forKey key: String) {
    put(NSNumber(value: value), key)
  }

  func set(_ value: Bool, forKey key: String) {
    put(NSNumber(value: value), key)
  }

  /// `nil` removes, as `UserDefaults.set(nil, forKey:)` does.
  func set(_ value: String?, forKey key: String) {
    put(value, key)
  }

  func removeObject(forKey key: String) {
    put(nil, key)
  }

  /// Writes what changed since the last commit. A no-op when nothing did or the file could not
  /// be loaded.
  func commit() {
    lock.lock()
    defer { lock.unlock() }
    ensureLoaded()
    guard loaded, dirty else { return }
    if write(values) { dirty = false }
  }

  // MARK: Internals (under `lock`)

  private func put(_ value: Any?, _ key: String) {
    lock.lock()
    defer { lock.unlock() }
    ensureLoaded()
    // Unloaded means unreadable: holding the value would let a later commit replace the file
    // with a partial picture.
    guard loaded else { return }
    if let value {
      values[key] = value
    } else if values.removeValue(forKey: key) == nil {
      return
    }
    dirty = true
  }

  private func ensureLoaded() {
    guard !loaded, !ProtectedDataGate.isDeferring, let url = Self.fileURL else { return }
    let fm = FileManager.default
    if fm.fileExists(atPath: url.path) {
      // Present but unreadable is the phone before its first unlock: try again later.
      guard let data = try? Data(contentsOf: url),
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
        let dict = plist as? [String: Any]
      else {
        NSLog("[iroh-location] runtime location state unreadable; deferring")
        return
      }
      values = dict
      loaded = true
      // A previous migration may have written the file and died before cleaning up.
      removeLegacyKeys()
      return
    }
    // No file: this is the first launch of a build that has it. Move what UserDefaults holds.
    let defaults = UserDefaults.standard
    var migrated: [String: Any] = [:]
    for (key, value) in defaults.dictionaryRepresentation()
    where Self.migratedPrefixes.contains(where: { key.hasPrefix($0) }) {
      migrated[key] = value
    }
    // Write before deleting: if the file cannot be written (still locked, disk full) the old
    // keys stay where the next attempt can find them.
    guard write(migrated) else { return }
    values = migrated
    loaded = true
    removeLegacyKeys()
  }

  private func removeLegacyKeys() {
    let defaults = UserDefaults.standard
    for key in defaults.dictionaryRepresentation().keys
    where Self.migratedPrefixes.contains(where: { key.hasPrefix($0) }) {
      defaults.removeObject(forKey: key)
    }
  }

  private func write(_ dict: [String: Any]) -> Bool {
    guard let dir = Self.directory, let url = Self.fileURL else { return false }
    do {
      if !FileManager.default.fileExists(atPath: dir.path) {
        AppDataBackupExclusion.exclude(dir)
      }
      let data = try PropertyListSerialization.data(
        fromPropertyList: dict, format: .binary, options: 0)
      try data.write(
        to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
      return true
    } catch {
      NSLog("[iroh-location] runtime location state not written: \(error.localizedDescription)")
      return false
    }
  }
}
