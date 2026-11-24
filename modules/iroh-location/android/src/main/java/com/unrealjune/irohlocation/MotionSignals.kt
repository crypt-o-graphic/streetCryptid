package com.unrealjune.irohlocation

import android.Manifest
import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.google.android.gms.location.ActivityRecognition
import com.google.android.gms.location.ActivityTransition
import com.google.android.gms.location.ActivityTransitionRequest
import com.google.android.gms.location.ActivityTransitionResult
import com.google.android.gms.location.DetectedActivity
import com.google.android.gms.location.Geofence
import com.google.android.gms.location.GeofencingEvent
import com.google.android.gms.location.GeofencingRequest
import com.google.android.gms.location.LocationServices

/**
 * The OS's own signals for "started moving" and "stopped", which [BackgroundLocationService] uses
 * in preference to inferring them, and the alarm that wakes it on schedule.
 *
 * - [ActivityTransitions]: Google Play services' activity recognition (the Transition API), the
 *   motion classifier on the low-power sensor hub. Needs Play services and, from Android 10, the
 *   physical-activity permission (`PermissionsGate`'s `motion` step).
 * - [StopFence]: a Play services geofence around the stop, the counterpart of iOS's
 *   `sc.stop-anchor` region. Needs Play services only.
 * - Without either, the service falls back to the significant-motion sensor and its own 10-minute
 *   dwell rule (see the service).
 * - [TickAlarm]: `AlarmManager`, because a coroutine `delay` does not run while the CPU sleeps,
 *   and with GPS off nothing else wakes it.
 *
 * All three deliver to [MotionReceiver], which hands the event to the running service.
 */
internal object MotionSignals {
  const val ACTION_ACTIVITY = "com.unrealjune.irohlocation.ACTIVITY_TRANSITION"
  const val ACTION_FENCE = "com.unrealjune.irohlocation.STOP_FENCE"
  const val ACTION_TICK = "com.unrealjune.irohlocation.TICK"

  /** Play services fills the intent's extras, so its PendingIntents must be mutable on 12+. */
  fun pendingIntent(context: Context, action: String, requestCode: Int, mutable: Boolean): PendingIntent {
    val intent = Intent(context, MotionReceiver::class.java).setAction(action)
    var flags = PendingIntent.FLAG_UPDATE_CURRENT
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      flags = flags or if (mutable) PendingIntent.FLAG_MUTABLE else PendingIntent.FLAG_IMMUTABLE
    } else if (!mutable && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      flags = flags or PendingIntent.FLAG_IMMUTABLE
    }
    return PendingIntent.getBroadcast(context, requestCode, intent, flags)
  }

  /** Whether the physical-activity permission is held (install-time before Android 10). */
  fun activityPermitted(context: Context): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
      context.checkSelfPermission(Manifest.permission.ACTIVITY_RECOGNITION) ==
        PackageManager.PERMISSION_GRANTED
}

/** Activity transitions: STILL entered means stopped; walking, running, cycling or driving means moving. */
internal class ActivityTransitions(private val context: Context) {
  private val pending =
    MotionSignals.pendingIntent(context, MotionSignals.ACTION_ACTIVITY, 0x5C20, mutable = true)

  fun start(onFailure: (Exception) -> Unit) {
    val transitions =
      MOVING.plus(DetectedActivity.STILL).map {
        ActivityTransition.Builder()
          .setActivityType(it)
          .setActivityTransition(ActivityTransition.ACTIVITY_TRANSITION_ENTER)
          .build()
      }
    try {
      ActivityRecognition.getClient(context)
        .requestActivityTransitionUpdates(ActivityTransitionRequest(transitions), pending)
        .addOnFailureListener(onFailure)
    } catch (e: SecurityException) {
      onFailure(e)
    }
  }

  fun stop() {
    try {
      ActivityRecognition.getClient(context).removeActivityTransitionUpdates(pending)
    } catch (e: SecurityException) {
      // Permission revoked since; nothing is registered for us any more.
    }
  }

  companion object {
    val MOVING =
      listOf(
        DetectedActivity.WALKING,
        DetectedActivity.RUNNING,
        DetectedActivity.ON_BICYCLE,
        DetectedActivity.IN_VEHICLE,
      )

    fun name(type: Int): String =
      when (type) {
        DetectedActivity.STILL -> "still"
        DetectedActivity.WALKING -> "walking"
        DetectedActivity.RUNNING -> "running"
        DetectedActivity.ON_BICYCLE -> "bicycle"
        DetectedActivity.IN_VEHICLE -> "vehicle"
        else -> "other"
      }
  }
}

/** An exit geofence around the stop. `INITIAL_TRIGGER_EXIT` covers a phone already outside it. */
internal class StopFence(private val context: Context) {
  private val pending =
    MotionSignals.pendingIntent(context, MotionSignals.ACTION_FENCE, 0x5C21, mutable = true)

  fun arm(anchor: Location, radiusM: Float, onFailure: (Exception) -> Unit) {
    val fence =
      Geofence.Builder()
        .setRequestId(FENCE_ID)
        .setCircularRegion(anchor.latitude, anchor.longitude, radiusM)
        .setExpirationDuration(Geofence.NEVER_EXPIRE)
        .setTransitionTypes(Geofence.GEOFENCE_TRANSITION_EXIT)
        .build()
    val request =
      GeofencingRequest.Builder()
        .setInitialTrigger(GeofencingRequest.INITIAL_TRIGGER_EXIT)
        .addGeofence(fence)
        .build()
    try {
      LocationServices.getGeofencingClient(context)
        .addGeofences(request, pending)
        .addOnFailureListener(onFailure)
    } catch (e: SecurityException) {
      onFailure(e)
    }
  }

  fun disarm() {
    LocationServices.getGeofencingClient(context).removeGeofences(pending)
  }

  private companion object {
    const val FENCE_ID = "sc.stop-anchor"
  }
}

/** The service's clock: one `ELAPSED_REALTIME_WAKEUP` alarm, re-set after each firing. */
internal class TickAlarm(private val context: Context) {
  private val pending =
    MotionSignals.pendingIntent(context, MotionSignals.ACTION_TICK, 0x5C22, mutable = false)
  private val alarms = context.getSystemService(AlarmManager::class.java)

  /**
   * `AndAllowWhileIdle`, so it fires in Doze (at most about once per nine minutes there, which is
   * far inside every interval it is used for). Exact when the app may (`SCHEDULE_EXACT_ALARM`),
   * since a moving phone's slot tick is worth being on time; inexact otherwise.
   */
  fun schedule(inMs: Long) {
    val alarms = alarms ?: return
    val at = SystemClock.elapsedRealtime() + inMs
    try {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || alarms.canScheduleExactAlarms()) {
        alarms.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending)
      } else {
        alarms.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending)
      }
    } catch (e: SecurityException) {
      alarms.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending)
    }
  }

  fun cancel() {
    alarms?.cancel(pending)
  }
}

/** Hands each signal to the running service; with no service running there is nothing to do. */
class MotionReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    val service = BackgroundLocationService.current()
    if (service == null) {
      Log.i(TAG, "${intent.action} with no service running; ignored")
      return
    }
    when (intent.action) {
      MotionSignals.ACTION_TICK -> service.onTick()
      MotionSignals.ACTION_ACTIVITY -> {
        if (!ActivityTransitionResult.hasResult(intent)) return
        val event = ActivityTransitionResult.extractResult(intent)?.transitionEvents?.lastOrNull()
        if (event != null && event.transitionType == ActivityTransition.ACTIVITY_TRANSITION_ENTER) {
          service.onActivity(event.activityType)
        }
      }
      MotionSignals.ACTION_FENCE -> {
        val event = GeofencingEvent.fromIntent(intent) ?: return
        if (event.hasError()) {
          Log.w(TAG, "stop fence error ${event.errorCode}")
          return
        }
        if (event.geofenceTransition == Geofence.GEOFENCE_TRANSITION_EXIT) service.onFenceExit()
      }
    }
  }

  private companion object {
    const val TAG = "IrohMotion"
  }
}
