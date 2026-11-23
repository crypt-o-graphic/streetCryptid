package com.unrealjune.irohlocation

import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Looper
import android.util.Log
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.location.CurrentLocationRequest
import com.google.android.gms.location.FusedLocationProviderClient
import com.google.android.gms.location.LocationRequest
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority

/**
 * Where [BackgroundLocationService] gets its positions, in its two states.
 *
 * Google Play services' fused provider where the phone has it ([FusedSource]); the platform
 * `LocationManager` everywhere else ([PlatformSource]), so a phone without Google (GrapheneOS,
 * /e/, a Huawei) still shares. The fused provider is preferred because it is what Android itself
 * recommends: it blends GPS, Wi-Fi and cell under one priority, so a request says how much accuracy
 * it is worth and the provider decides which radios that takes. The platform provider needs one
 * request per radio and spends GPS whether or not Wi-Fi would have done.
 */
internal interface LocationSource {
  /** `fused` or `platform`, for `location.runtime`. */
  val name: String

  /** Moving: a precise position at least every [intervalMs], once the phone has gone [distanceM]. */
  fun startMoving(intervalMs: Long, distanceM: Float)

  /**
   * Stopped: no GPS. Passive positions (fixes other apps asked for, which cost nothing), plus a
   * low-power network position when [withNetwork], for a phone with nothing else to notice leaving.
   */
  fun startStopped(intervalMs: Long, distanceM: Float, withNetwork: Boolean)

  fun stop()

  /** One cheap position (Wi-Fi or cell, never GPS), or null when none can be had. */
  fun currentPosition(onResult: (Location?) -> Unit)
}

internal object PlayServices {
  /**
   * Whether Google Play services is installed, enabled and recent enough. The client library is
   * always in the APK (expo-location brings it); this is what decides whether it can do anything.
   */
  fun available(context: Context): Boolean =
    try {
      GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context) ==
        ConnectionResult.SUCCESS
    } catch (e: Throwable) {
      false
    }
}

/**
 * Called with a refused request, so the service can report it (`authorization`) or, for the fused
 * provider, fall back to the platform one.
 */
internal typealias SourceFailure = (what: String, error: Exception) -> Unit

internal class FusedSource(
  context: Context,
  private val onLocation: (Location) -> Unit,
  private val onFailure: SourceFailure,
) : LocationSource {
  override val name = "fused"
  private val client: FusedLocationProviderClient =
    LocationServices.getFusedLocationProviderClient(context)
  private val listener = com.google.android.gms.location.LocationListener { onLocation(it) }

  override fun startMoving(intervalMs: Long, distanceM: Float) {
    request(
      LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, intervalMs)
        .setMinUpdateIntervalMillis(intervalMs)
        .setMinUpdateDistanceMeters(distanceM)
        .build(),
      "moving",
    )
  }

  override fun startStopped(intervalMs: Long, distanceM: Float, withNetwork: Boolean) {
    val priority = if (withNetwork) Priority.PRIORITY_LOW_POWER else Priority.PRIORITY_PASSIVE
    request(
      LocationRequest.Builder(priority, intervalMs).setMinUpdateDistanceMeters(distanceM).build(),
      "stopped",
    )
  }

  private fun request(request: LocationRequest, what: String) {
    try {
      client
        .requestLocationUpdates(request, listener, Looper.getMainLooper())
        .addOnFailureListener { onFailure("fused $what", it) }
    } catch (e: SecurityException) {
      onFailure("fused $what", e)
    }
  }

  override fun stop() {
    client.removeLocationUpdates(listener)
  }

  override fun currentPosition(onResult: (Location?) -> Unit) {
    try {
      client
        .getCurrentLocation(
          CurrentLocationRequest.Builder()
            .setPriority(Priority.PRIORITY_BALANCED_POWER_ACCURACY)
            .setMaxUpdateAgeMillis(60_000L)
            .build(),
          null,
        )
        .addOnCompleteListener { task -> onResult(if (task.isSuccessful) task.result else null) }
    } catch (e: SecurityException) {
      onResult(null)
    }
  }
}

/** The platform provider, for phones without Google Play services. */
internal class PlatformSource(
  private val context: Context,
  private val onLocation: (Location) -> Unit,
  private val onFailure: SourceFailure,
) : LocationSource {
  override val name = "platform"
  private val manager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
  private val listener = LocationListener { onLocation(it) }

  override fun startMoving(intervalMs: Long, distanceM: Float) {
    // Both radios, deliberately. GPS alone goes quiet indoors, which is where a phone spends most
    // of its day, and the network provider is what keeps a trail alive in a building.
    request(listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER), intervalMs, distanceM)
  }

  override fun startStopped(intervalMs: Long, distanceM: Float, withNetwork: Boolean) {
    val providers = mutableListOf(LocationManager.PASSIVE_PROVIDER)
    if (withNetwork) providers += LocationManager.NETWORK_PROVIDER
    request(providers, intervalMs, distanceM)
  }

  private fun request(providers: List<String>, intervalMs: Long, distanceM: Float) {
    val manager = manager ?: return
    for (provider in providers) {
      try {
        manager.requestLocationUpdates(provider, intervalMs, distanceM, listener, Looper.getMainLooper())
      } catch (e: SecurityException) {
        onFailure(provider, e)
      } catch (e: IllegalArgumentException) {
        Log.i(TAG, "provider $provider is unavailable on this device")
      }
    }
  }

  override fun stop() {
    manager?.removeUpdates(listener)
  }

  override fun currentPosition(onResult: (Location?) -> Unit) {
    val manager = manager
    if (manager == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
      onResult(null)
      return
    }
    try {
      manager.getCurrentLocation(LocationManager.NETWORK_PROVIDER, null, context.mainExecutor) {
        onResult(it)
      }
    } catch (e: SecurityException) {
      onResult(null)
    } catch (e: IllegalArgumentException) {
      onResult(null)
    }
  }

  private companion object {
    const val TAG = "IrohLocationSource"
  }
}
