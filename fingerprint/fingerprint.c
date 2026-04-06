/*
 * Based on fprintd util to verify a fingerprint
 * Copyright (C) 2008 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2020 Marco Trevisan <marco.trevisan@canonical.com>
 * Copyright (C) 2023 Alexandr Lutsai <s.lyra@ya.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <time.h>
#include <gio/gio.h>

#include "fingerprint.h"
#include "log.h"

static void display_message(struct FingerprintState *state, const char *fmt, ...) {
	va_list(args);
	va_start(args, fmt);
	vsnprintf(state->status, sizeof(state->status), fmt, args);
	va_end(args);

	state->sw_state->auth_state = AUTH_STATE_FINGERPRINT;
	state->sw_state->fingerprint_msg = state->status;
	damage_state(state->sw_state);
	schedule_indicator_clear(state->sw_state);
}

static void create_manager(struct FingerprintState *state) {
	g_autoptr(GError) error = NULL;
	state->connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (state->connection == NULL) {
		swaylock_log(LOG_ERROR, "Failed to connect to session bus: %s", error->message);
		display_message(state, "Fingerprint error");
		return;
	}

	state->manager = fprint_dbus_manager_proxy_new_sync(
		state->connection,
		G_DBUS_PROXY_FLAGS_NONE,
		"net.reactivated.Fprint",
		"/net/reactivated/Fprint/Manager",
		NULL, &error);
	if (state->manager == NULL) {
		swaylock_log(LOG_ERROR, "Failed to get Fprintd manager: %s", error->message);
		display_message(state, "Fingerprint error");
		return;
	}

	swaylock_log(LOG_DEBUG, "FPrint manager created");
}

static void open_device(struct FingerprintState *state) {
	state->device = NULL;
	g_autoptr(FprintDBusDevice) dev = NULL;
	g_autoptr(GError) error = NULL;
	g_autofree char *path = NULL;
	if (!fprint_dbus_manager_call_get_default_device_sync(state->manager, &path, NULL, &error)) {
		swaylock_log(LOG_ERROR, "Impossible to verify: %s", error->message);
		display_message(state, "Fingerprint error");
		return;
	}

	swaylock_log(LOG_DEBUG, "Fingerprint: using device %s", path);
	dev = fprint_dbus_device_proxy_new_sync(
		state->connection,
		G_DBUS_PROXY_FLAGS_NONE,
		"net.reactivated.Fprint",
		path, NULL, &error);
	if (error) {
		swaylock_log(LOG_ERROR, "failed to connect to device: %s", error->message);
		display_message(state, "Fingerprint error");
		return;
	}

	if (!fprint_dbus_device_call_claim_sync(dev, "", NULL, &error)) {
		swaylock_log(LOG_DEBUG, "failed to claim the device: %s(%d)", error->message, error->code);
		// fprintd may be holding a stale handle from before suspend. Try to
		// release it and claim again. This is safe to call even without having
		// successfully claimed the device - it just tells fprintd to drop
		// whatever handle it has.
		g_autoptr(GError) release_error = NULL;
		if (!fprint_dbus_device_call_release_sync(dev, NULL, &release_error)) {
			swaylock_log(LOG_DEBUG, "release after failed claim also failed: %s",
					release_error->message);
			return;
		}
		g_clear_error(&error);
		if (!fprint_dbus_device_call_claim_sync(dev, "", NULL, &error)) {
			swaylock_log(LOG_DEBUG, "failed to claim the device after release: %s(%d)",
					error->message, error->code);
			return;
		}
		swaylock_log(LOG_DEBUG, "claimed device after releasing stale handle");
	}

	swaylock_log(LOG_DEBUG, "FPrint device opened %s", path);
	state->device = g_steal_pointer (&dev);
}

static void proxy_signal_cb(GDBusProxy *proxy, const gchar *sender_name,
		const gchar *signal_name, GVariant *parameters, gpointer user_data);
static void release_callback(GObject *source_object, GAsyncResult *res,
		gpointer user_data);
static void stop_and_release_device(struct FingerprintState *state);

static void verify_result(GObject *object, const char *result, gboolean done, void *user_data) {
	struct FingerprintState *state = user_data;
	swaylock_log(LOG_INFO, "Verify result: %s (%s)", result, done ? "done" : "not done");
	state->match = g_str_equal(result, "verify-match");
	if (g_str_equal(result, "verify-retry-scan")) {
		display_message(state, "Retry");
		return;
	} else if (g_str_equal(result, "verify-swipe-too-short")) {
		display_message(state, "Retry, too short");
		return;
	} else if (g_str_equal(result, "verify-finger-not-centered")) {
		display_message(state, "Retry, not centered");
		return;
	} else if (g_str_equal(result, "verify-remove-and-retry")) {
		display_message(state, "Remove and retry");
		return;
	}

	if (g_str_equal(result, "verify-disconnected") ||
	    g_str_equal(result, "verify-unknown-error")) {
		stop_and_release_device(state);

		if (state->on_demand) {
			state->active = 0;
			swaylock_log(LOG_INFO,
					"Fingerprint device error/disconnect (%s), deactivating on-demand scanner",
					result);
			display_message(state, "Press ESC to retry fingerprint");
		} else {
			swaylock_log(LOG_INFO,
					"Fingerprint device error/disconnect (%s), will retry",
					result);
			display_message(state, "Fingerprint: reconnecting...");
		}
		return;
	}

	if(state->match) {
		display_message(state, "Fingerprint OK");
	} else {
		display_message(state, "Retry");
	}

	state->completed = TRUE;
	g_autoptr(GError) error = NULL;
	if (!fprint_dbus_device_call_verify_stop_sync(state->device, NULL, &error)) {
		swaylock_log(LOG_ERROR, "VerifyStop failed: %s", error->message);
		display_message(state, "Fingerprint error");
		return;
	}
}

static void verify_started_cb(GObject *obj, GAsyncResult *res, gpointer user_data) {
	struct FingerprintState *state = user_data;
	if (!fprint_dbus_device_call_verify_start_finish(FPRINT_DBUS_DEVICE(obj), res, &state->error)) {
		return;
	}

	swaylock_log(LOG_DEBUG, "Verify started!");
	state->started = TRUE;
}

static void proxy_signal_cb(GDBusProxy	*proxy,
							const gchar *sender_name,
							const gchar *signal_name,
							GVariant	*parameters,
							gpointer	 user_data)
{
	struct FingerprintState *state = user_data;
	if (!state->started) {
		return;
	}

	if (!g_str_equal(signal_name, "VerifyStatus")) {
		return;
	}

	const gchar *result;
	gboolean done;
	g_variant_get(parameters, "(&sb)", &result, &done);
	verify_result(G_OBJECT (proxy), result, done, user_data);
}

static void start_verify(struct FingerprintState *state) {
	/* This one is funny. We connect to the signal immediately to avoid
	 * race conditions. However, we must ignore any authentication results
	 * that happen before our start call returns.
	 * This is because the verify call itself may internally try to verify
	 * against fprintd (possibly using a separate account).
	 *
	 * To do so, we *must* use the async version of the verify call, as the
	 * sync version would cause the signals to be queued and only processed
	 * after it returns.
	 */
	fprint_dbus_device_call_verify_start(state->device, "any", NULL,
										 verify_started_cb,
										 state);

	/* Wait for verify start while discarding any VerifyStatus signals */
	while (!state->started && !state->error) {
		g_main_context_iteration(NULL, TRUE);
	}

	if (state->error) {
		swaylock_log(LOG_ERROR, "VerifyStart failed: %s", state->error->message);
		display_message(state, "Fingerprint error");
		g_clear_error(&state->error);
		return;
	}
}

static void release_callback(GObject *source_object, GAsyncResult *res,
							 gpointer user_data) {
}

// Tear down an active verify session and release the device cleanly.
// Safe to call at any point — checks state before each step.
static void stop_and_release_device(struct FingerprintState *state) {
	if (state->device == NULL) {
		return;
	}
	if (state->started) {
		GError *err = NULL;
		fprint_dbus_device_call_verify_stop_sync(state->device, NULL, &err);
		if (err) {
			swaylock_log(LOG_DEBUG, "VerifyStop on sleep: %s", err->message);
			g_error_free(err);
		}
		state->started = FALSE;
	}
	g_signal_handlers_disconnect_by_func(state->device, proxy_signal_cb, state);
	fprint_dbus_device_call_release(state->device, NULL, release_callback, NULL);
	g_clear_object(&state->device);
	state->completed = FALSE;
	state->match = FALSE;
}

static void prepare_for_sleep_cb(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data) {
	struct FingerprintState *state = user_data;
	gboolean going_to_sleep;
	g_variant_get(parameters, "(b)", &going_to_sleep);
	if (going_to_sleep) {
		swaylock_log(LOG_DEBUG, "PrepareForSleep: releasing fingerprint device before suspend");
		stop_and_release_device(state);
		display_message(state, "Fingerprint not yet available");
	} else {
		swaylock_log(LOG_DEBUG, "PrepareForSleep: resuming, fingerprint will reconnect");
	}
}

void fingerprint_init(struct FingerprintState *fingerprint_state,
					  struct swaylock_state *swaylock_state) {
	memset(fingerprint_state, 0, sizeof(struct FingerprintState));
	fingerprint_state->active = 1; /* default on; --fingerprint-on-demand overrides to 0 */
	fingerprint_state->sw_state = swaylock_state;
	create_manager(fingerprint_state);
	if (fingerprint_state->manager == NULL || fingerprint_state->connection == NULL) {
		return;
	}

	// Subscribe to logind's PrepareForSleep signal so we can cleanly release
	// the fingerprint device before suspend and let it reconnect after resume.
	fingerprint_state->sleep_subscription_id = g_dbus_connection_signal_subscribe(
		fingerprint_state->connection,
		"org.freedesktop.login1",
		"org.freedesktop.login1.Manager",
		"PrepareForSleep",
		"/org/freedesktop/login1",
		NULL,
		G_DBUS_SIGNAL_FLAGS_NONE,
		prepare_for_sleep_cb,
		fingerprint_state,
		NULL);
	if (fingerprint_state->sleep_subscription_id == 0) {
		swaylock_log(LOG_ERROR, "Failed to subscribe to PrepareForSleep signal");
	} else {
		swaylock_log(LOG_DEBUG, "Subscribed to PrepareForSleep");
	}
}

int fingerprint_verify(struct FingerprintState *fingerprint_state) {
	/* VerifyStatus signals are processing, do not wait for completion. */
	g_main_context_iteration (NULL, FALSE);
	if (!fingerprint_state->active) {
		return false;
	}
	if (fingerprint_state->manager == NULL ||
		fingerprint_state->connection == NULL) {
		return false;
	}

	if (fingerprint_state->device == NULL) {
		/* Backoff: don't hammer fprintd while it's restarting */
		if (fingerprint_state->retry_after > 0) {
			struct timespec now;
			clock_gettime(CLOCK_BOOTTIME, &now);
			int64_t now_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
			if (now_ms < fingerprint_state->retry_after) {
				return false;
			}
			fingerprint_state->retry_after = 0;
		}

		open_device(fingerprint_state);
		if (fingerprint_state->device == NULL) {
			/* fprintd not ready yet - back off 2s and tell the user */
			struct timespec now;
			clock_gettime(CLOCK_BOOTTIME, &now);
			fingerprint_state->retry_after =
				(int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + 2000;
			display_message(fingerprint_state, "Fingerprint not yet available");
			return false;
		}

		g_signal_connect(fingerprint_state->device, "g-signal", G_CALLBACK (proxy_signal_cb),
						 fingerprint_state);
		start_verify(fingerprint_state);
	}

	if (!fingerprint_state->completed) {
		return false;
	}

	if (!fingerprint_state->match) {
		fingerprint_state->completed = 0;
		fingerprint_state->match = 0;
		start_verify(fingerprint_state);
		return false;
	}

	return true;
}

void fingerprint_deinit(struct FingerprintState *fingerprint_state) {
	if (fingerprint_state->sleep_subscription_id > 0) {
		g_dbus_connection_signal_unsubscribe(fingerprint_state->connection,
				fingerprint_state->sleep_subscription_id);
		fingerprint_state->sleep_subscription_id = 0;
	}
	stop_and_release_device(fingerprint_state);
}
