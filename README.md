# swaylock-effects

Swaylock-effects is a fork of [swaylock](https://github.com/swaywm/swaylock)
which adds built-in screenshots and image manipulation effects like blurring.
It's inspired by [i3lock-color](https://github.com/PandorasFox/i3lock-color),
although the feature sets aren't perfectly overlapping.

This repository ([hboetes/swaylock-effects](https://github.com/hboetes/swaylock-effects))
is a fork of [mortie/swaylock-effects](https://github.com/mortie/swaylock-effects),
via [jirutka/swaylock-effects](https://github.com/jirutka/swaylock-effects),
both of which are now unmaintained.

## Security fixes in this fork

The following bugs were found and fixed during a code audit of the inherited
codebase:

- **`pam.c`: shadowed `pam_status` variable** — the inner loop redeclared
  `pam_status`, shadowing the outer variable. As a result, `pam_end()` and the
  final `exit()` always received `PAM_SUCCESS` regardless of the actual
  authentication result.
- **`loop.c`: unsafe `realloc()` in `loop_add_fd()`** — assigning `realloc()`
  directly to `loop->fds` meant a failed allocation would set `loop->fds` to
  NULL while leaking the old allocation, followed immediately by a NULL
  dereference write.
- **`cairo.c`: unchecked `malloc()` in `cairo_surface_duplicate()`** — the
  result was passed directly to `memcpy()` without a NULL check.
- **`effects.c`: unchecked `malloc()` in `effect_blur()`** — the scratch buffer
  was passed directly to `blur_once()` without a NULL check.
- **`effects.c`: `--effect-custom` removed** — this feature compiled and loaded
  user-supplied C files as lock screen effects at runtime, invoking `cc(1)` from
  within the lock screen process. It had no known users and has been removed
  along with `--time-effects`.


![Screenshot](https://raw.githubusercontent.com/hboetes/swaylock-effects/master/screenshot.png)

## Example Command

    swaylock \
        --screenshots \
        --clock \
        --indicator \
        --indicator-radius 100 \
        --indicator-thickness 7 \
        --effect-blur 7x5 \
        --effect-vignette 0.5:0.5 \
        --ring-color bb00cc \
        --key-hl-color 880033 \
        --line-color 00000000 \
        --inside-color 00000088 \
        --separator-color 00000000 \
        --grace 2 \
        --fade-in 0.2

## New Features

The main new features compared to upstream swaylock are:

* `--screenshots` to use screenshots instead of an image on disk or a color
* `--clock` to show date/time in the indicator
    * Use `--indicator` to make the indicator always active
    * Use `--timestr` and `--datestr` to set the date/time formats
      (using strftime-style formatting)
* `--submit-on-touch` to use your touchscreen to submit a password.
  If you can unlock your device with anything else than your password,
  this might come helpful to trigger PAM's authentication process.
* `--grace <seconds>` to set a password grace period, so that the password
  isn't required to unlock until some number of seconds have passed.
    * Used together with `--indicator`, the indicator is always shown,
      even in the grace period.
    * Used together with `--indicator-idle-visible`, the indicator is only
      visible after the grace period.
    * By default, a key press, a mouse event or a touch event will unlock
      during the grace period. Use `--grace-no-mouse` to not unlock as a response
      to a mouse event, and `--grace-no-touch` to not unlock as a response to
      a touch event.
* `--fade-in <seconds>` to make the lock screen fade in.
* `--indicator-image <path>` to display an image inside the indicator.
* `--text-clear <string>`, `--text-caps-lock <string>`, `--text-ver <string>`,
  and `--text-wrong <string>` to change the texts displayed inside the indicator.
* `-p, --fingerprint` to unlock with a fingerprint scanner via fprintd.
* `-P, --fingerprint-on-demand` for external fingerprint scanners that time out after ~2 minutes.
  Press ESC or C-u to activate the scanner after locking.
* `--image <path>` now accepts a directory, picking a random image file from it.
* Various effects which can be applied to the background image
    * `--effect-blur <radius>x<times>`: Blur the image (thanks to yvbbrjdr's
      fast box blur algorithm in
      [i3lock-fancy-rapid](https://github.com/yvbbrjdr/i3lock-fancy-rapid))
    * `--effect-pixelate <factor>`: Pixelate the image.
    * `--effect-scale <scale>`: Scale the image by a factor. This can be used
      to make other effects faster if you don't need the full resolution.
    * `--effect-greyscale`: Make the image greyscale.
    * `--effect-vignette <base>:<factor>`: Apply a vignette effect (range is 0-1).
    * `--effect-compose <position>;<size>;<gravity>;<path>`: Overlay another image.

New feature ideas are welcome as issues (though I may never get around to
implement them), new feature implementations are welcome as pull requests :)

## Installation

Install dependencies:

* meson \*
* wayland
* wayland-protocols \*
* libxkbcommon
* cairo
* gdk-pixbuf2 \*\*
* pam (optional)
* fprintd (optional: fingerprint support)
* [scdoc](https://git.sr.ht/~sircmpwn/scdoc) (optional: man pages) \*
* git \*
* openmp (if using a compiler other than GCC)

_\*Compile-time dep_

_\*\*Optional: required for background images other than PNG_

Run these commands:

    meson setup build
    meson compile -C build
    sudo meson install -C build

Check `meson_options.txt` for build options. So for example, if you want to build with fingerprint support, use `meson setup build -Dfingerprint=enabled`

On systems without PAM, you need to suid the swaylock binary:

    sudo chmod a+s /usr/local/bin/swaylock

Swaylock will drop root permissions shortly after startup.

## Effects

### Blur

`--effect-blur <radius>x<times>`: Blur the image.

`<radius>` is a number specifying how big
the blur is, `<times>` is a number which specifies essentially how high quality the blur is
(i.e how closely the effect will resemble a true gaussian blur).

### Pixelate

`--effect-pixelate <factor>`: Pixelate the image.

`<factor>` is the amount of pixelation; a value of 10 will make each 10x10 square of pixels
the same color.

### Scale

`--effect-scale <scale>`: Scale the image by a factor.

This effect scales the internal buffer. This has a few uses:

* Use `--effect-scale` in combination with `--scaling` to create a zoom effect:
  `--effect-scale 1.1 --scaling center`
* Speed up other effects by making the resolution smaller: with
  `--effect-scale 0.5 --effect-blur 7x5 --effect-scale 2`, swaylock-effect needs to blur
  only 1/4 as many pixels.

### Greyscale

`--effect-greyscale`: Make the displayed image greyscale.

### Vignette

`--effect-vignette <base>:<factor>`: Apply a vignette effect.
Base and factor should be between 0 and 1.

### Compose

`--effect-compose "<position>;<size>;<gravity>;<path>"`: Overlay another image to your lock screen.

* `<position>`: Optional. The position on the screen to put the image, as `<x>,<y>`.
    * Can be a percentage (`10%,10%`), a number of pixels (`20,20`), or a mix (`30%,40`).
    * A negative number indicates that number of pixels away from the right/bottom instead of
      from the top/left; `-1,-1` would be the bottom right pixel.
    * Default: `50%,50%`.
* `<size>`: Optional. The size of the image on the screen, as `<w>x<h>`.
    * Can be a percentage (`10%x10%`), a number of pixels (`20x20`), or a mix (`30%x40`).
    * If the width is `-1`, the width is figured out based on the height and aspect ratio.
    * If the height is `-1`, the height is figured out based on the width and aspect ratio.
    * Default: The size of the image file.
* `<gravity>`: Optional. Determine which point of the image is placed at `<position>`.
    * Possible values: `center`, `north`, `south`, `west`, `east`,
      `northwest`, `northeast`, `southwest`, `southeast`.
    * With a `<gravity>` of `northwest`, `<position>` gives the location of the top/left
      corner of the image; with `southeast`, `<position>` controls the bottom/right corner,
      `center` controls the middle of the image, etc.
    * Default: `center` if no `<position>` is given; otherwise, intelligently decide a gravity
      based on position (`10,10` -> northwest, `-10,10` -> northeast, etc).
* `<path>`: The path to an image file.

This command requires swaylock-effects to be compiled with gdk-pixbuf2.
It supports all image formats gdk-pixbuf2 supports; on my system, that's
png, jpeg, gif, svg, bmp, ico, tiff, wmf, ani, icns, pnm, qtif, tga, xbm and xpm.


### Integration into your window manager configuration
To make `swaylock-effect` easy to start from your window manager you could write a wrapper script, and add it to your `PATH`, something like this:

```
#!/bin/zsh

case "$1" in
    now)
        grace=0
        fade=0
        ;;
    *)
        grace=10
        fade=5
    ;;
esac

swaylock \
    --clock \
    --effect-vignette 0.5:0.5 \
    --fade-in $fade \
    --fingerprint \
    --indicator-caps-lock \
    --indicator-radius 100 \
    --indicator-thickness 7 \
    --inside-color 00000088 \
    --key-hl-color 880033 \
    --line-color 00000000 \
    --ring-color bb00cc \
    --separator-color 00000000 \
    --image $HOME/Wallpapers/lockscreen \
    --grace $grace
```
