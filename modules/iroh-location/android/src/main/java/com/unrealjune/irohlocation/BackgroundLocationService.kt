package com.unrealjune.irohlocation

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.TriggerEvent
import android.hardware.TriggerEventListener
import android.location.Location
import android.os.BatteryManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import com.google.android.gms.location.DetectedActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import uniffi.iroh_location.BatteryState
import uniffi.iroh_location.DataMode
import uniffi.iroh_location.LocationFix
import uniffi.iroh_location.LocationRuntimeKind

/**
 * A foreground service that takes each location straight to the wire, with no JS in the loop.
 *
 * The failure this replaces: `expo-location`'s task hands fixes to `expo-task-manager`, which needs
 * a headless JS context to deliver them to. When that context does not start — for eleven and a
 * half hours on a Pixel on 2026-08-29 — the events spool on disk and nothing publishes, while the
 * foreground service, the GPS and the outbox all look perfectly healthy. Here the same callback
 * that receives the location also seals and sends it.
 *
 * ## Play services where there are any, the platform everywhere else
 *
 * Positions come from the fused provider, stops and departures from activity recognition and a
 * geofence, all Google Play services, when the phone has them ([LocationSource], [MotionSignals]).
 * A phone without them must still share, so each has a platform fallback: `LocationManager`, the
 * significant-motion sensor and a dwell rule. Play services is never a hard dependency.
 *
 * ## Relationship to the JS pipeline
 *
 * They cannot both run: the Rust stores take a process-wide directory claim, so whichever starts
 * first owns the counter and the queue and the other stands down. That is deliberate and needs no
 * agreement between them — see [`NativeBackgroundRuntime`].
 */
class BackgroundLocationService : Service() {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
  private var source: LocationSource? = null
  private var activity: ActivityTransitions? = null
  private var fence: StopFence? = null
  private var tickAlarm: TickAlarm? = null

  /** The distance the moving request was made with, so a cadence change re-requests only on change. */
  private var movingDistanceM: Float = -1f

  /**
   * The publish cadence.
   *
   * It is the *slot* interval, not the sampling rate: the gate absorbs everything that arrives
   * inside a slot, so requesting updates more often than this costs battery and publishes nothing
   * extra. What it does buy is a fresher position at the moment a slot comes due.
   *
   * Held in the companion so the cadence controller can change it without a handle on the running
   * service — Android gives callers a component name, not an instance. It used to be a constant,
   * which meant a service that quietly ignored the interval the app was showing the user.
   */
  private val slotIntervalMs: ULong
    get() = cadenceSlotIntervalMs

  private fun onLocation(location: Location) {
    reporter.noteDelivery(location)
    if (stopped) {
      // A passive or network position while stopped. Near the stop it confirms the stop, which the
      // parked heartbeat already says; only a position clearly elsewhere is news.
      if (nearStop(location)) return
      enterMoving("departure")
    }
    lastLocation = location
    // Stamped before the launch, not inside it: the tick asks "did the provider deliver in this
    // slot", and a coroutine that has been dispatched but not yet run still answers yes.
    lastDeliveryAtMs = System.currentTimeMillis()
    // Straight into the native path. No JS, no headless bridge, no spool.
    launchAwake("publish") { publish(location) }
  }

  private fun nearStop(location: Location): Boolean {
    val anchor = stopAnchor ?: return false
    val slack = if (location.hasAccuracy()) location.accuracy else 0f
    return location.distanceTo(anchor) < DEPART_RADIUS_M + slack
  }

  /**
   * `moving` or `stopped`, the Android counterpart of the iOS runtime's states (June, 2026-11-22:
   * make Android like iOS, reporting while moving and only doing maintenance otherwise).
   *
   * It was a single state with GPS and network requested every minute for as long as sharing ran,
   * because a foreground service stays alive regardless. Staying alive was never the problem; the
   * GPS was. Stopped means no GPS: passive positions only, a stop fence, and a wake on the data
   * mode's maintenance interval ([maintenanceIntervalMs]), whose parked heartbeats the core floors
   * to the same cadence (`publish.rs`).
   *
   * What decides it, best first:
   * - activity recognition (`STILL` entered → stopped; walking, running, cycling, driving →
   *   moving), with Play services and the physical-activity permission;
   * - the stop fence's exit, with Play services;
   * - otherwise the significant-motion sensor for leaving, and no delivery past the 50 m filter for
   *   [STOP_AFTER_MS] for stopping (also the backstop when activity recognition never says `STILL`);
   * - and always a passive or maintenance position [DEPART_RADIUS_M] from the stop.
   */
  @Volatile private var stopped = false
  @Volatile private var stopAnchor: Location? = null
  @Volatile private var lastLocation: Location? = null
  private var sensorManager: SensorManager? = null
  private var significantMotion: Sensor? = null

  private val motionTrigger =
    object : TriggerEventListener() {
      override fun onTrigger(event: TriggerEvent?) {
        enterMoving("significant_motion")
      }
    }

  /**
   * When the provider last handed us a location, or 0 before the first one. The ticker reads it to
   * fill slots nothing delivered into, and to decide the phone has stopped (see [stopped]).
   */
  @Volatile private var lastDeliveryAtMs: Long = 0L

  /** `location.runtime`, so this service is visible when no JS is alive to say it is running. */
  private val reporter =
    LocationRuntimeReporter(
      scope,
      slotIntervalMs = { slotIntervalMs.toLong().coerceAtLeast(MIN_TICK_INTERVAL_MS) },
      distanceFilterM = { cadenceDistanceM },
    )

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onCreate() {
    super.onCreate()
    // A redelivered restart lands here with the app in the background, where Android 12+ refuses
    // the promotion. Uncaught, that refusal crashes the process and Android backs the next restart
    // off by months (`restartDelay=+218d` on a Pixel, 2026-10-21) — see [ServiceRecovery]. Caught,
    // it is a clean stop with a watchdog and a resume notification behind it.
    try {
      startForeground(NOTIFICATION_ID, notification())
    } catch (e: Exception) {
      ServiceRecovery.recordBlocked(applicationContext, "on-create: ${e.javaClass.simpleName}")
      stopSelf()
      return
    }
    running = true
    // The other way Android refuses: for a background-restricted app it logs "startForeground()
    // not allowed due to bg restriction" and returns normally, leaving an ordinary background
    // service the system will stop within minutes (seen on an emulator, 2026-10-22). Keep running
    // and publishing while it lasts, but treat it as the refusal it is.
    val promoted = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || foregroundServiceType != 0
    if (!promoted) {
      ServiceRecovery.recordBlocked(applicationContext, "on-create: not-foreground")
    } else {
      ServiceRecovery.noteStarted(applicationContext)
    }
    instance = this
    val play = PlayServices.available(this)
    source =
      if (play) FusedSource(this, ::onLocation, ::onFusedFailure)
      else PlatformSource(this, ::onLocation, ::onSourceFailure)
    if (play) fence = StopFence(this)
    sensorManager = getSystemService(Context.SENSOR_SERVICE) as? SensorManager
    significantMotion = sensorManager?.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION)
    refreshMotion()
    tickAlarm = TickAlarm(this)
    startMoving()
    scheduleTick()
    // Off the main thread: configuring telemetry loads the native library. A process restarted
    // with no JS (the app was killed and `START_REDELIVER_INTENT` brought this back) is exactly
    // the one with nobody else to configure it, so the `started` span goes out after it.
    scope.launch(Dispatchers.IO) {
      TelemetryConfigurator.applyPersisted(applicationContext)
      // Refusals since the last good start, reported now because the processes they happened in
      // may never have exported anything. `detail` carries the count, the gap and the last cause.
      // Only a start that actually reached the foreground ends the outage being reported.
      val blocked = if (promoted) ServiceRecovery.takeBlocked(applicationContext) else null
      // What brought the service back, and how long after the phone booted: a `trigger=boot` with
      // a small `boot_age_s` is the boot receiver working; a first start long after a boot, from
      // the app, is one that did not.
      val trigger = ServiceRecovery.takeStartTrigger(applicationContext) ?: "app-or-redeliver"
      val bootAgeS = SystemClock.elapsedRealtime() / 1000
      val origin =
        "trigger=$trigger boot_age_s=$bootAgeS source=${source?.name} " +
          "motion=${motionName()} fence=${fence != null}"
      Log.i(TAG, "service started: $origin promoted=$promoted")
      if (blocked != null) {
        val gapS = (System.currentTimeMillis() - blocked.firstAtMs) / 1000
        reporter.event(
          LocationRuntimeKind.STARTED,
          reason = "recovered",
          detail = "$origin fgs_start_blocked count=${blocked.count} gap_s=$gapS last=${blocked.reason}",
        )
      } else {
        reporter.event(
          LocationRuntimeKind.STARTED,
          reason = if (promoted) "service" else "service-not-foreground",
          detail = origin,
        )
      }
      ProcessMemorySampler.sample("started")
      reporter.startPulse()
    }
  }

  /**
   * `START_REDELIVER_INTENT`, matching what `expo-location`'s own service uses: a process kill
   * should bring the service back with its intent rather than silently drop sharing until the user
   * next opens the app.
   */
  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    // [setCadence] restarts the service to apply a new distance filter; `onCreate` does not run
    // again for a service already running, so the moving request is re-made here.
    if (running && !stopped && movingDistanceM != cadenceDistanceM) startMoving()
    return START_REDELIVER_INTENT
  }

  override fun onDestroy() {
    // False when `onCreate` was refused the foreground and stopped early: nothing was started, and
    // the background lease may belong to someone else in this process, so there is nothing to undo.
    val started = running
    running = false
    if (!started) {
      scope.cancel()
      super.onDestroy()
      return
    }
    instance = null
    reporter.stopPulse()
    tickAlarm?.cancel()
    activity?.stop()
    fence?.disarm()
    significantMotion?.let { sensorManager?.cancelTriggerSensor(motionTrigger, it) }
    source?.stop()
    source = null
    // Release the directory claims so a mounted app can take them back immediately, rather than
    // failing its first `createNode` until this process happens to be reaped.
    //
    // NOT `scope.launch`: the very next line cancels `scope`, and a coroutine cancelled before it is
    // dispatched never runs — which is what this did until 2026-10-03, so the release never happened.
    NativeBackgroundRuntime.stopDetached()
    scope.cancel()
    super.onDestroy()
  }

  private fun startMoving() {
    val source = source ?: return
    source.stop()
    movingDistanceM = cadenceDistanceM
    source.startMoving(MIN_UPDATE_INTERVAL_MS, cadenceDistanceM)
  }

  /** Whether anything other than a passive position can notice a departure. */
  private fun hasDepartureSignal(): Boolean =
    activity != null || fence != null || significantMotion != null

  /**
   * Activity recognition when Play services and the permission allow it, the significant-motion
   * sensor otherwise. Called at start and again from [refreshMotionActivity] once the permission
   * step has been answered, so a grant takes effect without restarting sharing.
   */
  @Synchronized
  internal fun refreshMotion() {
    if (activity != null) return
    if (!PlayServices.available(this) || !MotionSignals.activityPermitted(this)) return
    val transitions = ActivityTransitions(this)
    activity = transitions
    transitions.start { error ->
      Log.w(TAG, "activity transitions refused", error)
      synchronized(this) { if (activity === transitions) activity = null }
      reporter.event(
        LocationRuntimeKind.AUTHORIZATION,
        reason = "activity_refused",
        detail = error.message ?: error.javaClass.simpleName,
      )
    }
    // The sensor is the fallback; with activity recognition it would only duplicate it.
    if (stopped) significantMotion?.let { sensorManager?.cancelTriggerSensor(motionTrigger, it) }
  }

  private fun motionName(): String =
    when {
      activity != null -> "activity"
      significantMotion != null -> "significant_motion"
      else -> "none"
    }

  @Synchronized
  private fun enterStopped(reason: String) {
    if (stopped || !running) return
    stopped = true
    stopAnchor = lastLocation
    val source = source
    source?.stop()
    source?.startStopped(STOPPED_UPDATE_INTERVAL_MS, DEPART_RADIUS_M, withNetwork = !hasDepartureSignal())
    val sensorArmed =
      if (activity == null) {
        significantMotion?.let { sensorManager?.requestTriggerSensor(motionTrigger, it) } ?: false
      } else {
        false
      }
    val anchor = stopAnchor
    if (anchor != null) {
      armFence(anchor)
    } else {
      // No position yet this run: take one cheaply and centre the stop on it.
      source?.currentPosition { position ->
        if (position != null && stopped && stopAnchor == null) {
          stopAnchor = position
          armFence(position)
        }
      }
    }
    scheduleTick()
    reporter.event(
      LocationRuntimeKind.TRANSITION,
      reason = reason,
      detail =
        "moving->stopped gps=off motion=${motionName()} sensor=$sensorArmed " +
          "fence=${fence != null && anchor != null}",
    )
  }

  private fun armFence(anchor: Location) {
    fence?.arm(anchor, DEPART_RADIUS_M) { error ->
      Log.w(TAG, "stop fence refused", error)
      reporter.event(
        LocationRuntimeKind.FENCE_FAILED,
        reason = "stop_fence",
        detail = error.message ?: error.javaClass.simpleName,
      )
    }
  }

  @Synchronized
  private fun enterMoving(reason: String) {
    if (!stopped || !running) return
    stopped = false
    significantMotion?.let { sensorManager?.cancelTriggerSensor(motionTrigger, it) }
    fence?.disarm()
    // A full window to find the first fix before the dwell rule may decide the phone stopped again.
    lastDeliveryAtMs = System.currentTimeMillis()
    startMoving()
    // The next tick may be a whole maintenance interval away; back to slot cadence now.
    scheduleTick()
    reporter.event(LocationRuntimeKind.TRANSITION, reason = reason, detail = "stopped->moving")
  }

  /** From [MotionReceiver]: an activity transition was entered. */
  internal fun onActivity(type: Int) {
    val name = ActivityTransitions.name(type)
    when {
      type == DetectedActivity.STILL -> enterStopped("activity_$name")
      type in ActivityTransitions.MOVING -> enterMoving("activity_$name")
    }
  }

  /** From [MotionReceiver]: the stop fence reported an exit. */
  internal fun onFenceExit() {
    reporter.event(LocationRuntimeKind.FENCE_EXIT, reason = "stop_fence")
    enterMoving("fence_exit")
  }

  /** The fused provider refused: report it, and fall back to the platform provider for this run. */
  private fun onFusedFailure(what: String, error: Exception) {
    onSourceFailure(what, error)
    if (error is SecurityException) return
    synchronized(this) {
      if (source !is FusedSource || !running) return
      source?.stop()
      source = PlatformSource(this, ::onLocation, ::onSourceFailure)
      if (stopped) {
        source?.startStopped(
          STOPPED_UPDATE_INTERVAL_MS,
          DEPART_RADIUS_M,
          withNetwork = !hasDepartureSignal(),
        )
      } else {
        startMoving()
      }
    }
  }

  private fun onSourceFailure(what: String, error: Exception) {
    Log.w(TAG, "location request refused: $what", error)
    reporter.event(
      if (error is SecurityException) LocationRuntimeKind.AUTHORIZATION
      else LocationRuntimeKind.LOCATION_ERROR,
      reason = if (error is SecurityException) "denied" else "request_failed",
      detail = "$what: ${error.message ?: error.javaClass.simpleName}",
    )
  }

  private fun slotMs(): Long = slotIntervalMs.toLong().coerceAtLeast(MIN_TICK_INTERVAL_MS)

  private fun scheduleTick() {
    tickAlarm?.schedule(if (stopped) maintenanceIntervalMs(slotMs()) else slotMs())
  }

  /**
   * Run [block] with the CPU held awake. An alarm, a sensor trigger or a location callback wakes
   * the CPU only for as long as its own callback runs; a push and a pull take tens of seconds
   * after that, and a CPU that suspends mid-push resumes it whenever something next wakes the phone.
   */
  private fun launchAwake(tag: String, block: suspend () -> Unit) {
    val power = getSystemService(Context.POWER_SERVICE) as? PowerManager
    val lock =
      power?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "streetcryptid:$tag")?.apply {
        setReferenceCounted(false)
        acquire(WORK_WAKE_LOCK_MS)
      }
    scope.launch {
      try {
        block()
      } finally {
        if (lock?.isHeld == true) lock.release()
      }
    }
  }

  /**
   * The service's clock, fired by [TickAlarm]: every slot while moving, every maintenance interval
   * while stopped.
   *
   * ## Why this has to exist
   *
   * `requestLocationUpdates` delivers only when BOTH the interval has elapsed AND the device has
   * moved `cadenceDistanceM`. With a 50 m filter a phone on a desk produces **no callbacks at all,
   * indefinitely** — so the send path simply never ran, and the only thing publishing a stationary
   * Pixel's position was the deferrable `expo-background-task` refresh. On 2026-09-18 App Standby
   * decayed that from a run every ~16 minutes to one in fourteen hours, and the phone went silent
   * for 7.8 of them with `task.location_running = true`, `perm.background = granted` and every
   * other flag green.
   *
   * ## Why an alarm and not a timer
   *
   * It was a coroutine `delay` until 2026-11-22. That clock does not advance while the CPU is
   * suspended, and nothing holds the CPU awake for a parked phone: while GPS was requested every
   * minute its wakeups carried the timer along, but with GPS off for a stop a 30-minute delay could
   * last for hours. `ELAPSED_REALTIME_WAKEUP` counts sleep and wakes the CPU to fire.
   *
   * Lowering `cadenceDistanceM` to zero would also produce deliveries, and is the wrong fix: it
   * spins GPS for positions the gate will discard, and routes them through `ingest`, where failing
   * the movement test stamps `FIX_STATE_NO_FIX` for a phone that is parked. The heartbeat path
   * stamps `FIX_STATE_PARKED`, which is true.
   *
   * A moving tick is skipped whenever the provider delivered inside the current slot, so a moving
   * phone never publishes twice for one slot; `heartbeatFix` is idempotent against the slot grid
   * anyway.
   */
  internal fun onTick() {
    if (!running) return
    // The next one first, so nothing below can end the chain.
    scheduleTick()
    launchAwake("tick") {
      if (stopped) {
        maintenance()
        return@launchAwake
      }
      val slotMs = slotMs()
      val since = System.currentTimeMillis() - lastDeliveryAtMs
      // A delivery inside this slot means `publish` has already run the gate for it.
      if (lastDeliveryAtMs != 0L && since < slotMs) return@launchAwake
      // Nothing delivered for long enough with a 50 m filter: the phone is not moving.
      if (lastDeliveryAtMs == 0L || since >= STOP_AFTER_MS) enterStopped("dwell")
      heartbeat()
    }
  }

  /**
   * How long a stopped phone sleeps between maintenance wakes: the data mode's parked cadence
   * (Balanced 30 min, Saver 60 min, Real time every slot), the same floor the core applies to a
   * parked heartbeat (`dial_gate::parked_heartbeat_floor`). June, 2026-11-22: "we should still
   * wake the phone up every so often because we can, but certainly not every 5".
   */
  private fun maintenanceIntervalMs(slotMs: Long): Long {
    val mode =
      try {
        NodeStorage.host.current()?.dataMode()
      } catch (e: Exception) {
        null
      }
    return when (mode) {
      DataMode.REALTIME -> slotMs
      DataMode.SAVER -> 60 * 60_000L
      else -> 30 * 60_000L
    }.coerceAtLeast(slotMs)
  }

  /**
   * A stopped phone's periodic wake: the parked heartbeat (which also pulls friends, floored), and
   * one cheap Wi-Fi or cell position to catch a departure every other signal missed.
   */
  private suspend fun maintenance() {
    reporter.event(LocationRuntimeKind.PULSE, reason = "maintenance")
    heartbeat()
    source?.currentPosition { position ->
      if (position != null && stopped && !nearStop(position)) enterMoving("maintenance_check")
    }
  }

  private suspend fun heartbeat() {
    val battery = readBattery()
    reporter.noteWorkStarted()
    val capture =
      try {
        NativeBackgroundRuntime.heartbeat(applicationContext, battery, slotIntervalMs)
      } finally {
        reporter.noteWorkFinished()
      }
    when (capture) {
      is NativeBackgroundRuntime.Capture.Ingested -> Unit
      // Same hand-off as a capture: while the app is mounted it runs the pipeline's front half
      // (policy, own marker). `null` fix: a parked tick has no position, and `routeNativeCapture`
      // reads `kind` to know that.
      NativeBackgroundRuntime.Capture.HandToApp -> {
        reporter.noteHandOff()
        IrohLocationModule.handOffCapture(
          fix = null,
          battery = battery,
          reason = "periodic",
          kind = "heartbeat",
          state = "stopped",
          parked = true,
        )
        // The app publishes; receiving off screen is still ours. Declines while it is on screen.
        NativeBackgroundRuntime.pullAfterHandOff(applicationContext, trigger = "periodic")
      }
      NativeBackgroundRuntime.Capture.Unavailable -> Unit
    }
  }

  private suspend fun publish(location: Location) {
    val fix = location.toFix()
    val battery = readBattery()
    reporter.noteWorkStarted()
    val capture =
      try {
        NativeBackgroundRuntime.ingest(applicationContext, fix, battery, slotIntervalMs)
      } finally {
        reporter.noteWorkFinished()
      }
    when (capture) {
      is NativeBackgroundRuntime.Capture.Ingested -> {
        val outcome = capture.outcome
        // One line per wake that did something, so a quiet phone and a broken one look different
        // in logcat. The equivalent spans reach the collector from the Rust side.
        if (outcome.enqueued > 0u || outcome.published > 0u) {
          Log.i(
            TAG,
            "wake: enqueued=${outcome.enqueued} published=${outcome.published} " +
              "pending=${outcome.pending} skipped=${outcome.slotsSkipped} " +
              "dropped=${outcome.overflowDropped} suspended=${outcome.suspended}",
          )
        }
      }
      // The ordinary outcome whenever the app is alive. Handing it over IS the mounted path —
      // dropping here is what left a Pixel silent for fifteen hours with a perfectly healthy
      // service running.
      NativeBackgroundRuntime.Capture.HandToApp ->
        if (IrohLocationModule.handOffCapture(fix, battery, reason = "movement")) {
          reporter.noteHandOff()
          NativeBackgroundRuntime.pullAfterHandOff(applicationContext, trigger = "movement")
        } else {
          // The module was torn down between the routing decision and the hand-off. Unlike the
          // queued cases this fix is simply gone, so say so rather than letting it look routine.
          Log.w(TAG, "capture dropped: the app was wired a moment ago and is not any more")
        }
      // No identity, or the ingest threw. The fix stays in the native outbox for the next wake.
      NativeBackgroundRuntime.Capture.Unavailable -> Unit
    }
  }

  private fun Location.toFix(): LocationFix =
    LocationFix(
      lat = latitude,
      lon = longitude,
      // `hasAccuracy()` false means the provider gave us no radius, NOT a perfect one. Zero is how
      // the gate spells "untestable", so it skips the accuracy check rather than silently passing.
      accuracyM = if (hasAccuracy()) accuracy.toDouble() else 0.0,
      headingDeg = if (hasBearing()) bearing.toDouble() else 0.0,
      ts = time.toULong(),
      // Capture-side: the envelope stamps belong to a send that has not happened yet.
      state = null,
      publishedDeltaS = null,
    )

  /**
   * Battery inputs for the suspend decision.
   *
   * Unknown reports as full rather than empty: the gate treats a critical level as a hard stop, so
   * a device whose battery API we cannot read must not look flat and stop publishing forever.
   */
  private fun readBattery(): BatteryState {
    val status =
      registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        ?: return BatteryState(level = 1.0, charging = false, lowPower = false)
    val level = status.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
    val scale = status.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
    val plugged = status.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
    val power = getSystemService(Context.POWER_SERVICE) as? PowerManager
    return BatteryState(
      level = if (level >= 0 && scale > 0) level.toDouble() / scale.toDouble() else 1.0,
      charging = plugged != 0,
      lowPower = power?.isPowerSaveMode ?: false,
    )
  }

  private fun notification(): Notification {
    val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      // IMPORTANCE_LOW: required for an ongoing location service, and silent — a persistent
      // notification that made a sound every time the service restarted would be intolerable.
      manager.createNotificationChannel(
        NotificationChannel(CHANNEL_ID, "Location sharing", NotificationManager.IMPORTANCE_LOW)
      )
    }
    return Notification.Builder(this, CHANNEL_ID)
      .setContentTitle("Sharing your location")
      .setContentText("Your friends can see where you are.")
      .setSmallIcon(android.R.drawable.ic_menu_mylocation)
      .setOngoing(true)
      .build()
  }

  companion object {
    private const val TAG = "IrohBgService"

    /** Set by {@link setCadence}; read by the running service on its next fix. */
    @Volatile private var cadenceSlotIntervalMs: ULong = 5UL * 60UL * 1000UL
    @Volatile private var cadenceDistanceM: Float = 50f
    @Volatile private var running = false
    @Volatile private var instance: BackgroundLocationService? = null

    /** The running service, for [MotionReceiver]; null when sharing is off. */
    internal fun current(): BackgroundLocationService? = instance

    /** The physical-activity permission was just answered: start activity recognition if allowed. */
    fun refreshMotionActivity() {
      instance?.refreshMotion()
    }

    /** Whether the service is the one currently receiving locations. Reported by `device.health`. */
    fun isRunning(): Boolean = running

    /**
     * Re-program from the sampling policy's decision.
     *
     * Stored rather than applied directly: `LocationManager` has no re-arm, so a distance change
     * takes effect when the service next re-requests. The slot interval applies immediately,
     * because it is enforced on our side rather than by the provider.
     */
    fun setCadence(context: Context, intervalMs: Long, distanceM: Float) {
      cadenceSlotIntervalMs = intervalMs.coerceAtLeast(1L).toULong()
      if (distanceM != cadenceDistanceM) {
        cadenceDistanceM = distanceM
        // Cheapest correct re-arm: the service re-requests on start, and startForegroundService on
        // an already-running service just re-delivers the intent.
        if (running) start(context)
      }
    }
    private const val CHANNEL_ID = "streetcryptid.location-sharing"
    private const val NOTIFICATION_ID = 0x5C10

    /**
     * Ask the OS for updates far more often than we publish, and let the gate absorb the rest.
     *
     * The slot grid decides what actually goes out, so a tighter request does not increase the
     * publish rate — it only means the fix that lands on a slot boundary is recent rather than
     * minutes old. One minute and fifty metres is the same shape `AMBIENT_*` uses in JS.
     */
    private const val MIN_UPDATE_INTERVAL_MS = 60_000L

    /**
     * Floor on the stationary tick, independent of the user's chosen slot interval.
     *
     * The interval is user-selectable down to one minute (`SHARE_INTERVAL_OPTIONS_MS`), and a
     * heartbeat is cheap — no GPS, one sealed envelope — but this stops a future cadence change
     * from turning the ticker into a spin loop.
     */
    private const val MIN_TICK_INTERVAL_MS = 60_000L

    /** No delivery for this long, with the 50 m filter, and the phone is taken to have stopped. */
    private const val STOP_AFTER_MS = 10 * 60_000L

    /** While stopped, how far a passive or network position must be from the stop to mean "left". */
    private const val DEPART_RADIUS_M = 150f

    /** While stopped, the least interval asked of the passive (and fallback network) provider. */
    private const val STOPPED_UPDATE_INTERVAL_MS = 5 * 60_000L

    /** How long one tick's or one capture's work may hold the CPU awake: a push, then a pull. */
    private const val WORK_WAKE_LOCK_MS = 90_000L

    /** The user turned sharing on (or the cadence changed while it was on). */
    fun start(context: Context) {
      ServiceRecovery.setWanted(context, true)
      val intent = Intent(context, BackgroundLocationService::class.java)
      context.startForegroundService(intent)
    }

    /** The user turned sharing off: nothing may bring the service back until they turn it on. */
    fun stop(context: Context) {
      ServiceRecovery.setWanted(context, false)
      context.stopService(Intent(context, BackgroundLocationService::class.java))
    }
  }
}
