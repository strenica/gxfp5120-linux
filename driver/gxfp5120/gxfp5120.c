/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * GXFP5120 libfprint driver — Goodix GF3658 "Milan" behind the ITE EC SPI
 * bridge (Huawei MACHD-WXX9 / MateBook D 14, ACPI GXFP5120-family).
 *
 * One capture per biometric decision; templates are driver-private
 * (FPI_PRINT_RAW) serialized SigFM descriptor sets in the print's
 * "fpi-data" variant, matching the mb13 GXFP51A0 template schema.
 */
#define FP_COMPONENT "gxfp5120"

#include "fpi-device.h"
#include "fpi-log.h"
#include "fpi-print.h"

#include "gxfp5120.h"
#include "goodix_sift.h"

#define GX_TEMPLATE_VERSION 1u

struct _FpiDeviceGxfp5120
{
  FpDevice parent;

  GxDev dev;
  gchar *spidev_path; /* set in probe from the udev match */
  gint enroll_stage;  /* stages completed in the current enroll action */
};

G_DECLARE_FINAL_TYPE (FpiDeviceGxfp5120, fpi_device_gxfp5120,
                      FPI, DEVICE_GXFP5120, FpDevice);
G_DEFINE_TYPE (FpiDeviceGxfp5120, fpi_device_gxfp5120, FP_TYPE_DEVICE);

/* ---- template (print "fpi-data") ---- */

static GVariant *
views_to_variant (GPtrArray *views)
{
  GVariantBuilder b;
  GVariant *payload;
  guint i;

  g_variant_builder_init (&b, G_VARIANT_TYPE ("aay"));
  for (i = 0; i < views->len; i++)
    {
      g_autoptr(GByteArray) ba = gx_sift_serialize (g_ptr_array_index (views, i));
      g_variant_builder_add_value (
        &b, g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, ba->data, ba->len, 1));
    }
  payload = g_variant_builder_end (&b);
  return g_variant_new ("(u@aay)", GX_TEMPLATE_VERSION, payload);
}

static GPtrArray *
views_from_print (FpPrint *print)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) payload = NULL;
  GPtrArray *views = g_ptr_array_new_with_free_func ((GDestroyNotify) gx_sift_free);
  GVariantIter it;
  GVariant *child;
  guint32 version = 0;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data)
    return views;

  if (g_variant_is_of_type (data, G_VARIANT_TYPE ("(uaay)")))
    {
      g_variant_get (data, "(u@aay)", &version, &payload);
      if (version != GX_TEMPLATE_VERSION)
        {
          fp_warn ("unsupported template version %u (want %u); re-enroll",
                   version, GX_TEMPLATE_VERSION);
          return views;
        }
    }
  else
    {
      fp_warn ("unsupported template payload %s", g_variant_get_type_string (data));
      return views;
    }

  g_variant_iter_init (&it, payload);
  while ((child = g_variant_iter_next_value (&it)))
    {
      gsize len = 0;
      const guint8 *raw = g_variant_get_fixed_array (child, &len, 1);
      GxSiftFeatures *f = gx_sift_deserialize (raw, len);
      if (f)
        g_ptr_array_add (views, f);
      g_variant_unref (child);
    }
  return views;
}

/* error mapping: gate/"no image" failures are retryable (user presses again) */
static GError *
maybe_retry_error (GError *error)
{
  if (error && (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA) ||
                g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT)))
    {
      g_clear_error (&error);
      return fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
    }
  return error;
}

/* ---- open / close ---- */

static void
open_thread_func (GTask *task, gpointer source, gpointer task_data,
                  GCancellable *cancellable)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (source);
  g_autoptr(GError) error = NULL;

  if (!gx_dev_open (&self->dev, self->spidev_path, &error))
    g_task_return_error (task, g_steal_pointer (&error));
  else
    g_task_return_boolean (task, TRUE);
}

static void
open_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  g_autoptr(GError) error = NULL;

  g_task_propagate_boolean (G_TASK (res), &error);
  fpi_device_open_complete (FP_DEVICE (source), g_steal_pointer (&error));
}

static void
dev_open (FpDevice *dev)
{
  GTask *task = g_task_new (dev, NULL, open_done, NULL);

  g_task_run_in_thread (task, open_thread_func);
  g_object_unref (task);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (dev);

  gx_dev_close (&self->dev);
  fpi_device_close_complete (dev, NULL);
}

static void
dev_cancel (FpDevice *dev)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (dev);

  g_atomic_int_set (&self->dev.cancelled, 1);
}

/* ---- enroll ---- *
 *
 * fprintd/libfprint contract (1.94): ONE enroll action runs all
 * nr_enroll_stages captures inside the driver, calling
 * fpi_device_enroll_progress() after each stage and completing with the
 * accumulated FpPrint at the end.
 */

static void
enroll_stage_thread_func (GTask *task, gpointer source, gpointer task_data,
                          GCancellable *cancellable)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (source);
  g_autoptr(GError) error = NULL;
  void *feat = NULL;

  if (!gx_dev_capture_features (&self->dev, &feat, &error))
    g_task_return_error (task, g_steal_pointer (&error));
  else
    g_task_return_pointer (task, feat, NULL);
}

static void gx_enroll_launch_stage (FpDevice *dev);

static void
enroll_stage_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (source);
  g_autoptr(GError) error = NULL;
  FpPrint *print = NULL;
  g_autoptr(GPtrArray) views = NULL;
  GxSiftFeatures *feat = g_task_propagate_pointer (G_TASK (res), &error);

  if (error)
    {
      GError *mapped = maybe_retry_error (g_steal_pointer (&error));

      if (mapped->domain == FP_DEVICE_RETRY)
        {
          /* tell fprintd this scan failed (retryable) and arm again */
          fpi_device_enroll_progress (dev, self->enroll_stage, NULL, mapped);
          gx_enroll_launch_stage (dev);
          return;
        }
      fpi_device_enroll_complete (dev, NULL, mapped);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  views = views_from_print (print);
  if (views->len > 0)
    {
      GString *ps = g_string_new (NULL);
      int best_prior = 0;

      for (guint i = 0; i < views->len; i++)
        {
          int s = gx_dev_match_features (feat, g_ptr_array_index (views, i));

          if (s > best_prior)
            best_prior = s;
          g_string_append_printf (ps, " %d", s);
        }
      fp_info ("enroll: stage %d matches prior views:%s (best %d)",
               self->enroll_stage + 1, ps->str, best_prior);
      g_string_free (ps, TRUE);

    }
  g_ptr_array_add (views, feat);

  /* floating variant; g_object_set consumes the ref (see fp-print.c) */
  g_object_set (print, "fpi-data", views_to_variant (views), NULL);

  self->enroll_stage++;
  fp_info ("enroll: stage %d/%d captured (%u keypoints, %u views)",
           self->enroll_stage, GX_ENROLL_STAGES,
           gx_sift_keypoints (feat), views->len);
  fpi_device_enroll_progress (dev, self->enroll_stage, print, NULL);

  if (self->enroll_stage < GX_ENROLL_STAGES)
    gx_enroll_launch_stage (dev);
  else
    fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
gx_enroll_launch_stage (FpDevice *dev)
{
  GTask *task = g_task_new (dev, NULL, enroll_stage_done, NULL);

  g_task_run_in_thread (task, enroll_stage_thread_func);
  g_object_unref (task);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (dev);

  self->enroll_stage = 0;
  gx_enroll_launch_stage (dev);
}

/* Score a probe against all enrolled views; log per-view SIGFM scores and,
 * for the best view, the photometric raster metrics (overlap/zncc/agree)
 * from gx_sift_pixel_overlap_metrics — used to tune the acceptance gates. */
static int
gx_score_probe (const char *tag, void *probe, GPtrArray *views, int *out_zncc)
{
  int best = 0;
  guint best_i = 0;
  GString *scores = g_string_new (NULL);

  if (out_zncc)
    *out_zncc = 0;

  for (guint i = 0; i < views->len; i++)
    {
      int s = gx_dev_match_features (probe, g_ptr_array_index (views, i));

      g_string_append_printf (scores, " %d", s);
      if (s > best)
        {
          best = s;
          best_i = i;
        }
    }

  if (best > 0)
    {
      int inliers = 0, overlap = 0, zncc = 0, agree = 0;

      if (gx_sift_pixel_overlap_metrics (probe,
                                         g_ptr_array_index (views, best_i),
                                         &inliers, &overlap, &zncc, &agree))
        {
          if (out_zncc)
            *out_zncc = zncc;
          fp_info ("%s: scores[%u]:%s best=%d@%u pixel: inliers=%d overlap=%d "
                   "zncc=%d agree=%d",
                   tag, views->len, scores->str, best, best_i,
                   inliers, overlap, zncc, agree);
        }
      else
        fp_info ("%s: scores[%u]:%s best=%d@%u pixel: n/a",
                 tag, views->len, scores->str, best, best_i);
    }
  else
    {
      fp_info ("%s: scores[%u]:%s best=0", tag, views->len, scores->str);
    }

  g_string_free (scores, TRUE);
  return best;
}

/* ---- verify ---- */

typedef struct
{
  FpPrint *print;
  int best;
  int zncc;
} VerifyData;

static void
verify_thread_func (GTask *task, gpointer source, gpointer task_data,
                    GCancellable *cancellable)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (source);
  VerifyData *vd = task_data;
  g_autoptr(GError) error = NULL;
  g_autoptr(GPtrArray) views = NULL;
  void *feat = NULL;
  int best = 0;

  if (!gx_dev_capture_features (&self->dev, &feat, &error))
    {
      g_task_return_error (task, g_steal_pointer (&error));
      return;
    }

  views = views_from_print (vd->print);
  best = gx_score_probe ("verify", feat, views, &vd->zncc);
  gx_dev_free_features (feat);

  vd->best = best;
  g_task_return_boolean (task, TRUE);
}

static void
verify_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  VerifyData *vd = user_data;
  g_autoptr(GError) error = NULL;

  g_task_propagate_boolean (G_TASK (res), &error);
  if (error)
    {
      GError *mapped = maybe_retry_error (g_steal_pointer (&error));
      if (mapped->domain == FP_DEVICE_RETRY)
        {
          fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, mapped);
          fpi_device_verify_complete (dev, NULL);
        }
      else
        {
          fpi_device_verify_complete (dev, mapped);
        }
      return;
    }

  fpi_device_verify_report (dev,
                            (vd->best >= GX_MATCH_THRESHOLD &&
                             vd->zncc >= GX_ZNCC_FLOOR) ? FPI_MATCH_SUCCESS
                                                      : FPI_MATCH_FAIL,
                            NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
dev_verify (FpDevice *dev)
{
  VerifyData *vd = g_new0 (VerifyData, 1);
  GTask *task;

  fpi_device_get_verify_data (dev, &vd->print);
  task = g_task_new (dev, NULL, verify_done, vd);
  g_task_set_task_data (task, vd, g_free);
  g_task_run_in_thread (task, verify_thread_func);
  g_object_unref (task);
}

/* ---- identify ---- */

typedef struct
{
  GPtrArray *prints;
  FpPrint *match;
  int best;
  int zncc;
} IdentifyData;

static void
identify_data_free (IdentifyData *id)
{
  g_clear_pointer (&id->prints, g_ptr_array_unref);
  g_free (id);
}

static void
identify_thread_func (GTask *task, gpointer source, gpointer task_data,
                      GCancellable *cancellable)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (source);
  IdentifyData *id = task_data;
  g_autoptr(GError) error = NULL;
  void *feat = NULL;
  guint i;

  if (!gx_dev_capture_features (&self->dev, &feat, &error))
    {
      g_task_return_error (task, g_steal_pointer (&error));
      return;
    }

  id->best = 0;
  id->match = NULL;
  for (i = 0; i < id->prints->len; i++)
    {
      FpPrint *p = g_ptr_array_index (id->prints, i);
      g_autoptr(GPtrArray) views = views_from_print (p);
      int z = 0;
      int best = gx_score_probe ("identify", feat, views, &z);

      if (best > id->best)
        {
          id->best = best;
          id->zncc = z;
          id->match = p;
        }
    }
  gx_dev_free_features (feat);
  g_task_return_boolean (task, TRUE);
}

static void
identify_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  IdentifyData *id = user_data;
  g_autoptr(GError) error = NULL;

  g_task_propagate_boolean (G_TASK (res), &error);
  if (error)
    {
      GError *mapped = maybe_retry_error (g_steal_pointer (&error));
      if (mapped->domain == FP_DEVICE_RETRY)
        {
          fpi_device_identify_report (dev, NULL, NULL, mapped);
          fpi_device_identify_complete (dev, NULL);
        }
      else
        {
          fpi_device_identify_complete (dev, mapped);
        }
      return;
    }

  fp_info ("identify: best score %d zncc %d (%s)", id->best, id->zncc,
           (id->best >= GX_MATCH_THRESHOLD && id->zncc >= GX_ZNCC_FLOOR)
             ? "match" : "no match");
  fpi_device_identify_report (dev,
                              (id->best >= GX_MATCH_THRESHOLD &&
                               id->zncc >= GX_ZNCC_FLOOR) ? id->match : NULL,
                              NULL, NULL);
  fpi_device_identify_complete (dev, NULL);
}

static void
dev_identify (FpDevice *dev)
{
  IdentifyData *id = g_new0 (IdentifyData, 1);
  GTask *task;

  fpi_device_get_identify_data (dev, &id->prints);
  g_ptr_array_ref (id->prints);

  /* fprintd runs an identify before every enrollment for duplicate
   * detection; with an empty gallery there is nothing to match against,
   * so don't make the user press the sensor for it. */
  if (id->prints->len == 0)
    {
      fp_info ("identify: empty gallery, nothing to match");
      fpi_device_identify_report (dev, NULL, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
      identify_data_free (id);
      return;
    }

  task = g_task_new (dev, NULL, identify_done, id);
  g_task_set_task_data (task, id, (GDestroyNotify) identify_data_free);
  g_task_run_in_thread (task, identify_thread_func);
  g_object_unref (task);
}

/* ---- probe + class ---- */

static const FpIdEntry driver_ids[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_SPIDEV, .spi_acpi_id = "GXFP5120" },
  { .udev_types = 0 }
};

static void
dev_probe (FpDevice *dev)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (dev);
  g_autofree gchar *udev_spi = NULL;
  const char *env = g_getenv ("GXFP5120_SPIDEV");
  const char *spi;

  g_object_get (dev, "fpi-udev-data-spidev", &udev_spi, NULL);
  if (env && *env)
    spi = env;
  else if (udev_spi && *udev_spi)
    spi = udev_spi;
  else
    spi = "/dev/spidev0.0";

  if (g_file_test (spi, G_FILE_TEST_EXISTS))
    {
      self->spidev_path = g_strdup (spi);
      fpi_device_probe_complete (dev, "gxfp5120-spi", NULL, NULL);
    }
  else
    {
      fpi_device_probe_complete (
        dev, NULL, NULL,
        fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
    }
}

static void
fpi_device_gxfp5120_finalize (GObject *object)
{
  FpiDeviceGxfp5120 *self = FPI_DEVICE_GXFP5120 (object);

  gx_dev_close (&self->dev);
  gx_tls_clear (&self->dev.tls);
  g_clear_pointer (&self->dev.spi_path, g_free);
  g_clear_pointer (&self->dev.gpio_path, g_free);
  g_clear_pointer (&self->spidev_path, g_free);

  G_OBJECT_CLASS (fpi_device_gxfp5120_parent_class)->finalize (object);
}

static void
fpi_device_gxfp5120_init (FpiDeviceGxfp5120 *self)
{
  g_atomic_int_set (&self->dev.cancelled, 0);
}

static void
fpi_device_gxfp5120_class_init (FpiDeviceGxfp5120Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = fpi_device_gxfp5120_finalize;

  dev_class->id = "gxfp5120";
  dev_class->full_name = "Goodix GXFP5120 (ITE EC SPI)";
  dev_class->type = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table = driver_ids;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = GX_ENROLL_STAGES;

  dev_class->probe = dev_probe;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;
  dev_class->cancel = dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}
